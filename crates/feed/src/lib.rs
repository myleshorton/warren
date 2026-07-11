//! A signed, append-only log with per-block verifiability — the substrate's
//! Hypercore equivalent.
//!
//! A [`Log`] is owned by an ed25519 keypair; only the owner appends. Every block
//! is a leaf of a BLAKE3 Merkle tree, and the owner signs a
//! [`Head`] = `(len, root)` after each append. Given only the owner's
//! [`PublicKey`] and a `Head`, a peer can verify any single block against a
//! compact inclusion [`Proof`] — without holding the rest of the log. That is
//! what makes sparse, random-access sync possible: fetch block `i` plus its
//! proof, check it against the signed head, and trust it.
//!
//! This crate is pure and synchronous — no I/O, no clock. The sync *protocol*
//! (requesting blocks/proofs from peers over the [`driver`](../driver)) layers
//! on top; here we provide the verifiable primitives it exchanges.
//!
//! ```
//! use feed::{verify_block, verify_head, Log};
//! use crypto::Keypair;
//!
//! let mut log = Log::new(Keypair::generate());
//! log.append(b"first");
//! log.append(b"second");
//!
//! // A peer holds only the public key. It verifies the head, then any block.
//! let pk = log.public_key();
//! let head = log.head();
//! assert!(verify_head(&pk, &head));
//!
//! let proof = log.proof(1).unwrap();
//! assert!(verify_block(&pk, &head, 1, b"second", &proof));
//! assert!(!verify_block(&pk, &head, 1, b"tampered", &proof));
//! ```

mod tree;

use crypto::{Hash, Keypair, PublicKey, Signature, HASH_LEN, SIGNATURE_LEN};
use thiserror::Error;
use wire::{Decoder, Encoder, WireError};

pub use tree::leaf_hash;

/// Domain tag mixed into the signed head, so a log-head signature can never be
/// mistaken for a signature over anything else this keypair signs.
const HEAD_DOMAIN: &[u8] = b"warren-log-head-v1";

/// Maximum siblings in a valid inclusion proof: the tree height for a `u64`
/// length is at most 64 (`log2(2^64)`), so any longer proof is malformed. A hard
/// cap keeps a network-facing `Proof::decode` from allocating on a crafted count.
const MAX_PROOF_SIBLINGS: usize = 64;

/// A signed commitment to the log's current contents: its length and Merkle
/// root, plus the owner's signature over them. Everything a peer needs to
/// verify blocks against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// Number of blocks in the log.
    pub len: u64,
    /// Merkle root over those blocks.
    pub root: Hash,
    /// The owner's signature over `(len, root)` (domain-separated).
    pub signature: Signature,
}

/// A compact inclusion proof: the sibling hashes from a block's leaf up to the
/// root (deepest first). Verified against a [`Head`] by [`verify_block`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The audit path — sibling hashes from the leaf to the root.
    pub siblings: Vec<Hash>,
}

/// A signed, append-only log owned by a keypair.
///
/// # Cost
///
/// [`Log::append`] is O(1) amortized (O(log n) worst case, when the accumulator
/// carries a run of equal-height peaks), and [`Log::root`] / [`Log::head`] are
/// **O(log n)**: the root is maintained by an incremental Merkle accumulator that
/// keeps only the right-spine subtree roots, so a commit doesn't rescan the whole
/// log. Per-block
/// inclusion proofs ([`Log::proof`]) still recompute their audit path from the
/// leaves and are O(n); making those O(log n) would mean retaining every internal
/// node, which is deferred.
pub struct Log {
    keypair: Keypair,
    blocks: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
    /// Incrementally-maintained subtree roots, so [`Log::root`] is O(log n).
    roots: tree::Accumulator,
}

impl Log {
    /// Create an empty log owned by `keypair`.
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            blocks: Vec::new(),
            leaves: Vec::new(),
            roots: tree::Accumulator::new(),
        }
    }

    /// The owner's public key — the log's stable identity.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// Number of blocks appended.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the log has no blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Append a block, returning its index.
    pub fn append(&mut self, block: impl Into<Vec<u8>>) -> usize {
        let block = block.into();
        let leaf = tree::leaf_hash(&block);
        self.leaves.push(leaf); // kept for O(n) inclusion proofs
        self.roots.push(leaf); // O(log n) root maintenance
        self.blocks.push(block);
        self.blocks.len() - 1
    }

    /// The block at `index`, if present.
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.blocks.get(index).map(Vec::as_slice)
    }

    /// The current Merkle root over all blocks — O(log n) from the accumulator.
    pub fn root(&self) -> Hash {
        self.roots.root()
    }

    /// A signed [`Head`] committing to the log's current length and root.
    pub fn head(&self) -> Head {
        let len = self.blocks.len() as u64;
        let root = self.root();
        let signature = self.keypair.sign(&head_message(len, &root));
        Head {
            len,
            root,
            signature,
        }
    }

    /// An inclusion proof for the block at `index` (against the current head),
    /// or `None` if `index` is out of range.
    pub fn proof(&self, index: usize) -> Option<Proof> {
        if index >= self.blocks.len() {
            return None;
        }
        Some(Proof {
            siblings: tree::audit_path(&self.leaves, index),
        })
    }
}

/// A readable feed: the three things a sync server needs to answer for — the
/// current signed head, a block by index, and that block's inclusion proof. The
/// owner's writable [`Log`] and a read-only [`Replica`] of someone else's feed
/// both implement it, so a server can serve from either.
pub trait Source {
    /// The current signed head.
    fn head(&self) -> Head;
    /// The block at `index`, if present.
    fn get(&self, index: usize) -> Option<&[u8]>;
    /// An inclusion proof for the block at `index` against the head, or `None`.
    fn proof(&self, index: usize) -> Option<Proof>;
}

impl Source for Log {
    fn head(&self) -> Head {
        Log::head(self)
    }
    fn get(&self, index: usize) -> Option<&[u8]> {
        Log::get(self, index)
    }
    fn proof(&self, index: usize) -> Option<Proof> {
        Log::proof(self, index)
    }
}

/// A verified, read-only copy of *another* owner's feed: their signed [`Head`]
/// plus the blocks it commits to. Unlike a [`Log`] it holds no keypair, so it can
/// neither append nor re-sign — only serve what it was given. A blind mirror uses
/// one to hold and serve a feed on the author's behalf (store-and-forward), and a
/// subscriber can tail from any replica-holder, not only the author.
pub struct Replica {
    public_key: PublicKey,
    head: Head,
    blocks: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
}

impl Replica {
    /// Build a replica from a feed's signed `head` and its `blocks` in order.
    /// Returns `None` unless the copy is provably faithful: the head verifies under
    /// `public_key`, the block count matches `head.len`, and the blocks reproduce
    /// `head.root`. So a mirror can neither invent a feed nor serve a doctored one —
    /// a replica that exists is a real, complete prefix of the owner's feed.
    pub fn new(public_key: PublicKey, head: Head, blocks: Vec<Vec<u8>>) -> Option<Replica> {
        if !verify_head(&public_key, &head) || blocks.len() as u64 != head.len {
            return None;
        }
        let leaves: Vec<Hash> = blocks.iter().map(|b| tree::leaf_hash(b)).collect();
        if tree::merkle_root(&leaves) != head.root {
            return None;
        }
        Some(Replica {
            public_key,
            head,
            blocks,
            leaves,
        })
    }

    /// The replicated feed's owner (the key its head is verified against).
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
    /// Number of blocks held.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }
    /// Whether the replica holds no blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Advance to a newer signed `head` by appending `new_blocks` — the blocks from
    /// the current length up to `head.len`, in order. Returns `false` and leaves the
    /// replica **unchanged** unless the result is provably faithful: `head` verifies
    /// under the owner's key, `new_blocks` exactly fills `len()..head.len`, and the
    /// combined blocks reproduce `head.root`. A live mirror calls this as it tails
    /// the author, growing the replica it serves. Advancing to the same head with no
    /// new blocks is an accepted no-op.
    pub fn advance(&mut self, head: Head, new_blocks: Vec<Vec<u8>>) -> bool {
        if !verify_head(&self.public_key, &head)
            || self.blocks.len() as u64 + new_blocks.len() as u64 != head.len
        {
            return false;
        }
        // Compute the combined leaves and check the root *before* mutating, so a
        // bad advance can't leave a torn replica.
        let mut leaves = self.leaves.clone();
        leaves.extend(new_blocks.iter().map(|b| tree::leaf_hash(b)));
        if tree::merkle_root(&leaves) != head.root {
            return false;
        }
        self.blocks.extend(new_blocks);
        self.leaves = leaves;
        self.head = head;
        true
    }
}

impl Source for Replica {
    fn head(&self) -> Head {
        self.head.clone()
    }
    fn get(&self, index: usize) -> Option<&[u8]> {
        self.blocks.get(index).map(Vec::as_slice)
    }
    fn proof(&self, index: usize) -> Option<Proof> {
        (index < self.blocks.len()).then(|| Proof {
            siblings: tree::audit_path(&self.leaves, index),
        })
    }
}

/// The exact bytes the owner signs for a head: a domain tag, the length, and the
/// root. Both signing and verification go through this, so they can't diverge.
fn head_message(len: u64, root: &Hash) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.bytes(HEAD_DOMAIN);
    enc.uint(len);
    enc.raw(root);
    enc.into_vec()
}

/// Verify a [`Head`]'s signature against the log owner's `public_key`. Does not
/// prove anything about individual blocks — pair with [`verify_block`].
pub fn verify_head(public_key: &PublicKey, head: &Head) -> bool {
    public_key
        .verify(&head_message(head.len, &head.root), &head.signature)
        .is_ok()
}

/// Verify that `block` really is block `index` of the log committed to by `head`
/// (which must itself be signed by `public_key`). This is the whole point: a
/// peer trusts a block on the strength of the signed head plus the proof, never
/// the sender.
pub fn verify_block(
    public_key: &PublicKey,
    head: &Head,
    index: u64,
    block: &[u8],
    proof: &Proof,
) -> bool {
    // Cheap bounds check first: an out-of-range index short-circuits before the
    // (comparatively expensive) signature verification. Then verify the head
    // signature, then the block's inclusion proof against it.
    index < head.len
        && verify_head(public_key, head)
        && verify_block_proof(head, index, block, proof)
}

/// Verify a block's inclusion proof against an *already-trusted* `head` — the
/// proof only, no head-signature check.
///
/// Use when the head's signature was verified separately and won't change: a
/// sync session verifies the head once, then many blocks against it, so calling
/// [`verify_block`] per block would redundantly re-verify the same signature.
/// [`verify_block`] is exactly this plus the head-signature check.
pub fn verify_block_proof(head: &Head, index: u64, block: &[u8], proof: &Proof) -> bool {
    if index >= head.len {
        return false;
    }
    // Convert to usize rather than cast: on a 32-bit target a huge signed `len`
    // would otherwise truncate and verify against the wrong tree shape. If it
    // doesn't fit this platform, the block simply can't be verified here.
    let (Ok(index), Ok(len)) = (usize::try_from(index), usize::try_from(head.len)) else {
        return false;
    };
    let leaf = tree::leaf_hash(block);
    tree::root_from_path(leaf, index, len, &proof.siblings) == Some(head.root)
}

/// Errors decoding a [`Head`] or [`Proof`] from bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LogError {
    /// A length field exceeded what the buffer could hold.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// The underlying byte codec rejected the buffer.
    #[error(transparent)]
    Wire(#[from] WireError),
}

impl Head {
    /// Encode the head for transfer.
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.uint(self.len);
        enc.raw(&self.root);
        enc.raw(&self.signature.to_bytes());
        enc.into_vec()
    }

    /// Decode a head from bytes.
    pub fn decode(buf: &[u8]) -> Result<Head, LogError> {
        let mut dec = Decoder::new(buf);
        let len = dec.uint()?;
        // The rest of the crate indexes with usize, so a length that can't fit
        // this platform's usize (only possible on <64-bit targets) is malformed
        // rather than silently truncated.
        if usize::try_from(len).is_err() {
            return Err(LogError::Malformed("length exceeds usize"));
        }
        let root = dec.array::<HASH_LEN>()?;
        let signature = Signature::from_bytes(dec.array::<SIGNATURE_LEN>()?);
        dec.finish()?;
        Ok(Head {
            len,
            root,
            signature,
        })
    }
}

impl Proof {
    /// Encode the proof for transfer.
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.uint(self.siblings.len() as u64);
        for sibling in &self.siblings {
            enc.raw(sibling);
        }
        enc.into_vec()
    }

    /// Decode a proof from bytes.
    pub fn decode(buf: &[u8]) -> Result<Proof, LogError> {
        let mut dec = Decoder::new(buf);
        let count = dec.uint()?;
        // A valid proof has at most `MAX_PROOF_SIBLINGS` hashes; reject anything
        // longer outright, and also bound by the buffer so a crafted length
        // within the cap still can't over-allocate relative to the bytes present.
        if count > MAX_PROOF_SIBLINGS as u64 {
            return Err(LogError::Malformed("proof exceeds maximum length"));
        }
        if count > dec.remaining() as u64 / HASH_LEN as u64 {
            return Err(LogError::Malformed("sibling count exceeds buffer"));
        }
        let mut siblings = Vec::with_capacity(count as usize);
        for _ in 0..count {
            siblings.push(dec.array::<HASH_LEN>()?);
        }
        dec.finish()?;
        Ok(Proof { siblings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_with(n: usize) -> Log {
        let mut log = Log::new(Keypair::from_seed(&[7u8; 32]));
        for i in 0..n {
            log.append(vec![i as u8; i + 1]);
        }
        log
    }

    #[test]
    fn appended_blocks_read_back() {
        let log = log_with(4);
        assert_eq!(log.len(), 4);
        assert_eq!(log.get(0), Some([0u8; 1].as_slice()));
        assert_eq!(log.get(3), Some([3u8; 4].as_slice()));
        assert_eq!(log.get(4), None);
    }

    #[test]
    fn every_block_verifies_against_the_signed_head() {
        let log = log_with(10);
        let pk = log.public_key();
        let head = log.head();
        assert!(verify_head(&pk, &head));
        for i in 0..log.len() {
            let proof = log.proof(i).unwrap();
            assert!(
                verify_block(&pk, &head, i as u64, log.get(i).unwrap(), &proof),
                "block {i} should verify"
            );
        }
        assert!(log.proof(10).is_none());
    }

    #[test]
    fn verify_block_proof_checks_inclusion_without_the_signature() {
        let log = log_with(8);
        let head = log.head();
        for i in 0..log.len() {
            let proof = log.proof(i).unwrap();
            // Proof-only verification accepts every real block against the head.
            assert!(verify_block_proof(
                &head,
                i as u64,
                log.get(i).unwrap(),
                &proof
            ));
        }
        // It still rejects a tampered block and an out-of-range index...
        let proof0 = log.proof(0).unwrap();
        assert!(!verify_block_proof(&head, 0, b"tampered", &proof0));
        assert!(!verify_block_proof(&head, 99, log.get(0).unwrap(), &proof0));
        // ...but, unlike verify_block, does NOT check the head signature: a head
        // with a bad signature but the real root still passes proof-only (that's
        // the caller's responsibility to have verified once).
        let forged = Head {
            signature: Keypair::from_seed(&[0xAB; 32]).sign(b"nonsense"),
            ..head.clone()
        };
        assert!(verify_block_proof(&forged, 0, log.get(0).unwrap(), &proof0));
        assert!(!verify_block(
            &log.public_key(),
            &forged,
            0,
            log.get(0).unwrap(),
            &proof0
        ));
    }

    #[test]
    fn a_tampered_block_fails_verification() {
        let log = log_with(6);
        let pk = log.public_key();
        let head = log.head();
        let proof = log.proof(2).unwrap();
        assert!(!verify_block(&pk, &head, 2, b"wrong bytes", &proof));
    }

    #[test]
    fn a_block_at_the_wrong_index_fails() {
        let log = log_with(6);
        let pk = log.public_key();
        let head = log.head();
        let proof = log.proof(2).unwrap();
        // Right block+proof, wrong claimed index.
        assert!(!verify_block(&pk, &head, 4, log.get(2).unwrap(), &proof));
    }

    #[test]
    fn a_head_from_another_key_is_rejected() {
        let log = log_with(4);
        let head = log.head();
        let attacker = Keypair::from_seed(&[9u8; 32]).public();
        assert!(!verify_head(&attacker, &head));
    }

    #[test]
    fn a_forged_head_over_the_real_root_is_rejected() {
        // A peer can't fabricate a head for someone else's log even with the
        // correct root — the signature is over (len, root) by the owner's key.
        let log = log_with(4);
        let head = log.head();
        let attacker = Keypair::from_seed(&[9u8; 32]);
        let forged = Head {
            len: head.len,
            root: head.root,
            signature: attacker.sign(&head_message(head.len, &head.root)),
        };
        assert!(!verify_head(&log.public_key(), &forged));
    }

    #[test]
    fn head_and_proof_roundtrip() {
        let log = log_with(7);
        let head = log.head();
        assert_eq!(Head::decode(&head.encode()).unwrap(), head);
        for i in 0..log.len() {
            let proof = log.proof(i).unwrap();
            assert_eq!(Proof::decode(&proof.encode()).unwrap(), proof);
        }
    }

    #[test]
    fn replica_faithfully_preserves_a_feed() {
        let log = log_with(10);
        let pk = log.public_key();
        let head = log.head();
        let blocks: Vec<Vec<u8>> = (0..log.len())
            .map(|i| log.get(i).unwrap().to_vec())
            .collect();

        let replica = Replica::new(pk, head.clone(), blocks).expect("faithful replica");
        assert_eq!(replica.len(), 10);
        assert_eq!(replica.head(), head); // same signed head — not re-signed
        for i in 0..replica.len() {
            assert_eq!(replica.get(i), log.get(i));
            let proof = replica.proof(i).unwrap();
            // The replica's recomputed proof verifies against the owner's head.
            assert!(verify_block(
                &pk,
                &head,
                i as u64,
                replica.get(i).unwrap(),
                &proof
            ));
        }
        assert!(replica.proof(10).is_none());
    }

    #[test]
    fn replica_rejects_an_unfaithful_copy() {
        let log = log_with(5);
        let pk = log.public_key();
        let head = log.head();
        let blocks: Vec<Vec<u8>> = (0..log.len())
            .map(|i| log.get(i).unwrap().to_vec())
            .collect();

        // Wrong owner key.
        let attacker = Keypair::from_seed(&[0x11; 32]).public();
        assert!(Replica::new(attacker, head.clone(), blocks.clone()).is_none());
        // A doctored block: the blocks no longer reproduce the signed root.
        let mut tampered = blocks.clone();
        tampered[2] = b"evil".to_vec();
        assert!(Replica::new(pk, head.clone(), tampered).is_none());
        // A truncated copy: count doesn't match head.len.
        let mut short = blocks;
        short.pop();
        assert!(Replica::new(pk, head, short).is_none());
    }

    #[test]
    fn an_empty_feed_replicates() {
        let log = log_with(0);
        let replica = Replica::new(log.public_key(), log.head(), vec![]).expect("empty replica");
        assert!(replica.is_empty());
        assert_eq!(replica.head(), log.head());
    }

    #[test]
    fn replica_advance_grows_and_stays_faithful() {
        let mut log = log_with(3);
        let pk = log.public_key();
        let blocks: Vec<Vec<u8>> = (0..3).map(|i| log.get(i).unwrap().to_vec()).collect();
        let mut replica = Replica::new(pk, log.head(), blocks).unwrap();
        assert_eq!(replica.len(), 3);

        // The author appends two blocks; the mirror advances its replica to match.
        log.append(vec![3u8; 4]);
        log.append(vec![4u8; 5]);
        let new = vec![log.get(3).unwrap().to_vec(), log.get(4).unwrap().to_vec()];
        assert!(replica.advance(log.head(), new));
        assert_eq!(replica.len(), 5);

        // Every block, old and new, still verifies against the advanced head.
        let head = log.head();
        for i in 0..replica.len() {
            let proof = replica.proof(i).unwrap();
            assert!(verify_block(
                &pk,
                &head,
                i as u64,
                replica.get(i).unwrap(),
                &proof
            ));
        }

        // A non-contiguous advance (wrong new-block count) is rejected, unchanged.
        assert!(!replica.advance(log.head(), vec![b"extra".to_vec()]));
        assert_eq!(replica.len(), 5);
    }

    #[test]
    fn decode_rejects_an_overlong_proof() {
        // A count above the height cap is rejected before allocating.
        let mut enc = wire::Encoder::new();
        enc.uint(MAX_PROOF_SIBLINGS as u64 + 1);
        assert_eq!(
            Proof::decode(&enc.into_vec()),
            Err(LogError::Malformed("proof exceeds maximum length"))
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let log = log_with(3);
        let mut bytes = log.head().encode();
        bytes.push(0xff);
        assert!(matches!(
            Head::decode(&bytes),
            Err(LogError::Wire(WireError::TrailingBytes(1)))
        ));
    }
}
