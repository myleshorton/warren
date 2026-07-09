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
/// [`Log::append`] is O(1) (it stores the block and its leaf hash), but
/// [`Log::root`], [`Log::head`], and [`Log::proof`] recompute Merkle roots from
/// the leaves on each call — O(n) in the number of blocks. That is fine for
/// moderate logs and keeps this first version simple and obviously correct; a
/// large log that commits/serves proofs frequently would want an incremental
/// Merkle accumulator that caches subtree roots (making `head`/`proof`
/// O(log n)). That optimization is deferred.
pub struct Log {
    keypair: Keypair,
    blocks: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
}

impl Log {
    /// Create an empty log owned by `keypair`.
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            blocks: Vec::new(),
            leaves: Vec::new(),
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
        self.leaves.push(tree::leaf_hash(&block));
        self.blocks.push(block);
        self.blocks.len() - 1
    }

    /// The block at `index`, if present.
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.blocks.get(index).map(Vec::as_slice)
    }

    /// The current Merkle root over all blocks.
    pub fn root(&self) -> Hash {
        tree::merkle_root(&self.leaves)
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
    if !verify_head(public_key, head) || index >= head.len {
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
