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

mod store;
mod tree;

use crypto::{Hash, Keypair, PublicKey, Signature, HASH_LEN, SIGNATURE_LEN};
use std::sync::Arc;
use thiserror::Error;
use wire::{Decoder, Encoder, WireError};

pub use store::{Batch, FeedKey, FeedStore, MemStore, StoreError, StoreResult};
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
/// [`Log::append`] is O(1) amortized, and [`Log::root`] / [`Log::head`] are **O(log n)**:
/// the root is maintained by an incremental Merkle accumulator that keeps only the
/// right-spine peaks in RAM. Per-block inclusion proofs ([`Log::proof`]) are **O(log n)**
/// too — the tree's frozen interior nodes are persisted in the store and read on demand,
/// so a proof holds neither the leaves nor the whole tree in memory.
pub struct Log {
    keypair: Keypair,
    /// Where blocks and the Merkle tree nodes live — a fresh [`MemStore`] for [`Log::new`],
    /// or a shared/persistent backend via [`Log::with_store`].
    store: Arc<dyn FeedStore>,
    feed: FeedKey,
    /// The append-only tree's peaks, kept in RAM (O(log n)); its frozen interior nodes
    /// live in the store. Together they answer `root`/`head`/`proof` without holding the
    /// leaves — so a large feed isn't RAM-bound and a proof is O(log n) store reads.
    roots: tree::Accumulator,
}

/// Seed a tree accumulator for a feed of `len` blocks held in `store`.
///
/// Fast path: read just the peak nodes (O(log n)) if the tree is persisted. Fallback: walk
/// the blocks once, rebuild the peaks, and backfill the `nodes` table — the one-time O(n)
/// cost for a Phase-A feed (blocks but no persisted tree) or a fresh open. After the
/// backfill, every later open takes the fast path.
fn seed_accumulator(
    store: &Arc<dyn FeedStore>,
    feed: &FeedKey,
    len: u64,
) -> StoreResult<tree::Accumulator> {
    if let Some(acc) =
        tree::Accumulator::from_peaks(len, |idx| store.node(feed, idx).ok().flatten())
    {
        return Ok(acc);
    }
    let mut roots = tree::Accumulator::new();
    let mut frozen = Vec::new();
    for i in 0..len {
        let block = store
            .block(feed, i)?
            .ok_or_else(|| StoreError::Backend(format!("dense feed missing block {i} of {len}")))?;
        frozen.extend(roots.push(tree::leaf_hash(&block)));
    }
    if !frozen.is_empty() {
        store.commit(
            feed,
            Batch {
                blocks: Vec::new(),
                nodes: frozen,
                head: None,
            },
        )?;
    }
    Ok(roots)
}

impl Log {
    /// Create an empty log owned by `keypair`, backed by a fresh in-memory store.
    pub fn new(keypair: Keypair) -> Self {
        // An empty [`MemStore`] is infallible, so opening over it cannot fail.
        Self::with_store(keypair, Arc::new(MemStore::new()))
            .expect("opening a log over an empty MemStore never fails")
    }

    /// Open a log over `store`, seeding the in-RAM peaks from the persisted tree (O(log n)
    /// peak reads) — so a persisted feed reopens intact and new appends land in `store`. A
    /// Phase-A feed (blocks but no tree yet) is backfilled once on first open; see
    /// [`seed_accumulator`].
    pub fn with_store(keypair: Keypair, store: Arc<dyn FeedStore>) -> StoreResult<Self> {
        let feed = keypair.public().to_bytes();
        let len = store.contiguous_len(&feed)?;
        let roots = seed_accumulator(&store, &feed, len)?;
        Ok(Self {
            keypair,
            store,
            feed,
            roots,
        })
    }

    /// The owner's public key — the log's stable identity.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// Number of blocks appended.
    pub fn len(&self) -> usize {
        self.roots.len() as usize
    }

    /// Whether the log has no blocks.
    pub fn is_empty(&self) -> bool {
        self.roots.len() == 0
    }

    /// A handle to the backing store, so a caller (e.g. a session) can share it with the
    /// feeds it mirrors — keeping the own log and every mirror in one store.
    pub fn store(&self) -> Arc<dyn FeedStore> {
        self.store.clone()
    }

    /// The current peak nodes as `(flat index, hash)` — what a provider hands a sparse
    /// subscriber (with the head) so it can open a [`Replica::sparse`] and verify blocks it
    /// later ingests, without downloading the whole feed.
    pub fn peak_nodes(&self) -> Vec<(u64, Hash)> {
        self.roots.peak_nodes()
    }

    /// Append a block, returning its index. Persists to the backing store atomically;
    /// panics if the store fails — impossible for the default in-memory backend. Use
    /// [`try_append`](Log::try_append) where a disk-backed store's failure must surface.
    pub fn append(&mut self, block: impl Into<Vec<u8>>) -> usize {
        self.try_append(block)
            .expect("feed store commit failed on append")
    }

    /// Append a block, returning its index — the fallible form.
    ///
    /// Commits to the backing store **before** advancing in-RAM state, so a store failure
    /// (disk full, corruption) leaves the log exactly as it was rather than desynced ahead
    /// of what's persisted.
    pub fn try_append(&mut self, block: impl Into<Vec<u8>>) -> StoreResult<usize> {
        let block = block.into();
        let leaf = tree::leaf_hash(&block);
        let index = self.roots.len();
        // Push into a prospective accumulator — without mutating self — to get the new head
        // and the nodes this append freezes, then persist block + frozen nodes + head in one
        // atomic commit. Only on success do we adopt the advanced accumulator.
        let mut roots = self.roots.clone();
        let frozen = roots.push(leaf);
        let len = index + 1;
        let root = roots.root();
        let signature = self.keypair.sign(&head_message(len, &root));
        let head = Head {
            len,
            root,
            signature,
        };
        self.store.commit(
            &self.feed,
            Batch {
                blocks: vec![(index, block)],
                nodes: frozen,
                head: Some(head),
            },
        )?;
        self.roots = roots;
        Ok(index as usize)
    }

    /// The block at `index`, if present. Returns an owned copy (the bytes live in the
    /// store, not this struct); `None` if absent or on a read error.
    pub fn get(&self, index: usize) -> Option<Vec<u8>> {
        self.store.block(&self.feed, index as u64).ok().flatten()
    }

    /// The current Merkle root over all blocks — O(log n) from the accumulator.
    pub fn root(&self) -> Hash {
        self.roots.root()
    }

    /// A signed [`Head`] committing to the log's current length and root.
    pub fn head(&self) -> Head {
        let len = self.roots.len();
        let root = self.root();
        let signature = self.keypair.sign(&head_message(len, &root));
        Head {
            len,
            root,
            signature,
        }
    }

    /// An inclusion proof for the block at `index` (against the current head), assembled
    /// from the persisted frozen nodes + the in-RAM peaks. `None` if `index` is out of
    /// range or a needed node is missing from the store.
    pub fn proof(&self, index: usize) -> Option<Proof> {
        self.roots
            .proof(index as u64, |idx| {
                self.store.node(&self.feed, idx).ok().flatten()
            })
            .map(|siblings| Proof { siblings })
    }
}

/// A readable feed: the three things a sync server needs to answer for — the
/// current signed head, a block by index, and that block's inclusion proof. The
/// owner's writable [`Log`] and a read-only [`Replica`] of someone else's feed
/// both implement it, so a server can serve from either.
pub trait Source {
    /// The current signed head.
    fn head(&self) -> Head;
    /// The block at `index`, if present. Owned, since a store-backed source can't lend a
    /// reference into its backend.
    fn get(&self, index: usize) -> Option<Vec<u8>>;
    /// An inclusion proof for the block at `index` against the head, or `None`.
    fn proof(&self, index: usize) -> Option<Proof>;
    /// The feed's peak nodes as `(flat index, hash)`, largest peak first — what a sparse
    /// subscriber needs (with the head) to open a [`Replica::sparse`] and verify blocks it
    /// later fetches, without downloading the whole feed.
    fn peaks(&self) -> Vec<(u64, Hash)>;
    /// The half-open index ranges `[start, end)` this source holds, ascending and
    /// non-adjacent. The default is the single dense range `[0, len)` — correct for a full
    /// [`Log`] and a dense [`Replica`]; a *sparse* holder overrides it to report its
    /// scattered windows. A subscriber intersects these with what it wants so it only asks
    /// a peer for blocks that peer actually holds.
    fn held_ranges(&self) -> Vec<(u64, u64)> {
        let len = self.head().len;
        if len == 0 {
            Vec::new()
        } else {
            vec![(0, len)]
        }
    }
}

impl Source for Log {
    fn head(&self) -> Head {
        Log::head(self)
    }
    fn get(&self, index: usize) -> Option<Vec<u8>> {
        Log::get(self, index)
    }
    fn proof(&self, index: usize) -> Option<Proof> {
        Log::proof(self, index)
    }
    fn peaks(&self) -> Vec<(u64, Hash)> {
        Log::peak_nodes(self)
    }
    // held_ranges: the default `[0, len)` is exact — a Log is always dense.
}

/// A verified, read-only copy of *another* owner's feed: their signed [`Head`]
/// plus the blocks it commits to. Unlike a [`Log`] it holds no keypair, so it can
/// neither append nor re-sign — only serve what it was given. A blind mirror uses
/// one to hold and serve a feed on the author's behalf (store-and-forward), and a
/// subscriber can tail from any replica-holder, not only the author.
pub struct Replica {
    public_key: PublicKey,
    /// Where the mirrored blocks live — a fresh [`MemStore`] via [`Replica::new`], or a
    /// shared/persistent backend via [`Replica::with_store`].
    store: Arc<dyn FeedStore>,
    feed: FeedKey,
    head: Head,
    /// The tree peaks (RAM); its frozen interior nodes live in the store. Used to verify
    /// each [`advance`](Replica::advance) and answer proofs without holding the leaves.
    roots: tree::Accumulator,
}

impl Replica {
    /// Build a replica from a feed's signed `head` and its `blocks` in order, holding them
    /// in a fresh in-memory store.
    ///
    /// Returns `None` unless the copy is provably faithful: the head verifies under
    /// `public_key`, the block count matches `head.len`, and the blocks reproduce
    /// `head.root`. So a mirror can neither invent a feed nor serve a doctored one —
    /// a replica that exists is a real, complete prefix of the owner's feed.
    pub fn new(public_key: PublicKey, head: Head, blocks: Vec<Vec<u8>>) -> Option<Replica> {
        Self::with_store(public_key, head, blocks, Arc::new(MemStore::new()))
    }

    /// Build a replica over `store` (shared or persistent). Same faithfulness check as
    /// [`new`](Replica::new); the verified blocks + head are committed to `store`.
    pub fn with_store(
        public_key: PublicKey,
        head: Head,
        blocks: Vec<Vec<u8>>,
        store: Arc<dyn FeedStore>,
    ) -> Option<Replica> {
        if !verify_head(&public_key, &head) || blocks.len() as u64 != head.len {
            return None;
        }
        let mut roots = tree::Accumulator::new();
        let mut frozen = Vec::new();
        for b in &blocks {
            frozen.extend(roots.push(tree::leaf_hash(b)));
        }
        if roots.root() != head.root {
            return None;
        }
        let feed = public_key.to_bytes();
        let batch = Batch {
            blocks: blocks
                .into_iter()
                .enumerate()
                .map(|(i, b)| (i as u64, b))
                .collect(),
            nodes: frozen,
            head: Some(head.clone()),
        };
        store.commit(&feed, batch).ok()?;
        Some(Replica {
            public_key,
            store,
            feed,
            head,
            roots,
        })
    }

    /// Re-open a replica already held in `store` (no re-commit) — how a mirror is
    /// restored from disk on restart. Reads the stored head + blocks, rebuilds the in-RAM
    /// leaves, and verifies them against the head. Returns `Ok(None)` if the store holds
    /// no head for this feed, or if the stored copy fails verification (corrupt on disk).
    pub fn open(public_key: PublicKey, store: Arc<dyn FeedStore>) -> StoreResult<Option<Replica>> {
        let feed = public_key.to_bytes();
        let Some(head) = store.head(&feed)? else {
            return Ok(None);
        };
        // Seed the peaks (O(log n) if the tree is persisted, else a one-time block rebuild).
        // Any reconstruction problem (missing block/node) is treated as "not faithful".
        let roots = match seed_accumulator(&store, &feed, head.len) {
            Ok(roots) => roots,
            Err(_) => return Ok(None),
        };
        if !verify_head(&public_key, &head) || roots.root() != head.root {
            return Ok(None); // tampered/corrupt on disk — treat as absent, don't serve it
        }
        Ok(Some(Replica {
            public_key,
            store,
            feed,
            head,
            roots,
        }))
    }

    /// Open a **sparse** replica from a feed's signed `head` and its `peak_nodes`
    /// (`(flat index, hash)`) — holding no blocks yet. Verifies the head and that the peaks
    /// reproduce its root, then seeds the accumulator so serving + proofs work for blocks
    /// later brought in by [`ingest`](Replica::ingest). This is how a windowed mirror or an
    /// on-access cache starts: it learns the feed's shape (root + len) without downloading
    /// it, then fills in a subset.
    pub fn sparse(
        public_key: PublicKey,
        head: Head,
        peak_nodes: Vec<(u64, Hash)>,
        store: Arc<dyn FeedStore>,
    ) -> Option<Replica> {
        if !verify_head(&public_key, &head) {
            return None;
        }
        let feed = public_key.to_bytes();
        store
            .commit(
                &feed,
                Batch {
                    blocks: Vec::new(),
                    nodes: peak_nodes,
                    head: Some(head.clone()),
                },
            )
            .ok()?;
        let roots =
            tree::Accumulator::from_peaks(head.len, |idx| store.node(&feed, idx).ok().flatten())?;
        if roots.root() != head.root {
            return None; // the peaks don't reproduce the signed root — reject
        }
        Some(Replica {
            public_key,
            store,
            feed,
            head,
            roots,
        })
    }

    /// Bring one block into a sparse replica: verify `block` at `index` against the held
    /// head and `proof`, and if it checks out, persist the block plus the within-peak proof
    /// nodes needed to re-serve it. Returns `false` (storing nothing) on a verification or
    /// store failure. After a successful ingest the replica serves and proves that block
    /// like any other.
    pub fn ingest(&mut self, index: u64, block: Vec<u8>, proof: &Proof) -> bool {
        if !verify_block(&self.public_key, &self.head, index, &block, proof) {
            return false;
        }
        let nodes = tree::proof_nodes(self.head.len, index, &proof.siblings);
        self.store
            .commit(
                &self.feed,
                Batch {
                    blocks: vec![(index, block)],
                    nodes,
                    head: None,
                },
            )
            .is_ok()
    }

    /// Prune to a suffix window: drop every held block below `below` and every Merkle node
    /// no longer needed to prove a retained block, keeping only `[below, len)` servable. The
    /// head, length, and peaks are untouched — the replica still knows the feed's full shape
    /// and root; it just no longer holds (or can prove) the pruned prefix. This is the
    /// bounded-footprint primitive a windowed seeder calls as the author's feed grows.
    /// Idempotent, and a no-op for `below == 0`.
    pub fn prune(&self, below: u64) {
        let retain = tree::retained_node_indices(self.head.len, below);
        // Best-effort: a store failure here only leaves extra data on disk, never corrupts
        // what's retained (the kept set is a strict superset of what proofs need).
        let _ = self.store.prune(&self.feed, below, &retain);
    }

    /// The replicated feed's owner (the key its head is verified against).
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
    /// Number of blocks held.
    pub fn len(&self) -> usize {
        self.roots.len() as usize
    }
    /// Whether the replica holds no blocks.
    pub fn is_empty(&self) -> bool {
        self.roots.len() == 0
    }

    /// The block at `index`, if held — an owned copy (the bytes live in the store). A
    /// holder (e.g. a mirror) reads these to serve or render the author's content on its
    /// behalf, even while the author is offline.
    pub fn block(&self, index: usize) -> Option<Vec<u8>> {
        self.store.block(&self.feed, index as u64).ok().flatten()
    }

    /// The replica's peak nodes as `(flat index, hash)`, largest peak first — the O(log n)
    /// tops of the tree, which a holder re-serves to a downstream sparse subscriber (with
    /// the head) so it can verify blocks without the whole feed.
    pub fn peak_nodes(&self) -> Vec<(u64, Hash)> {
        self.roots.peak_nodes()
    }

    /// The half-open index ranges this replica actually holds, ascending and coalesced. A
    /// dense replica returns `[0, len)`; a sparse one (built via [`Replica::sparse`] +
    /// [`ingest`](Replica::ingest)) returns only the windows it has. Computed by scanning
    /// block presence in the store — O(len) reads, so a caller that serves it repeatedly
    /// should cache it.
    pub fn held_ranges(&self) -> Vec<(u64, u64)> {
        let len = self.head.len;
        let mut ranges = Vec::new();
        let mut start: Option<u64> = None;
        for i in 0..len {
            let held = self.store.has_block(&self.feed, i).unwrap_or(false);
            match (held, start) {
                (true, None) => start = Some(i),
                (false, Some(s)) => {
                    ranges.push((s, i));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = start {
            ranges.push((s, len));
        }
        ranges
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
            || self.roots.len() + new_blocks.len() as u64 != head.len
        {
            return false;
        }
        // Push into a clone and check the root *before* mutating, so a bad advance leaves
        // the replica unchanged; the clone's pushes yield the nodes to persist.
        let start = self.roots.len();
        let mut roots = self.roots.clone();
        let mut frozen = Vec::new();
        for b in &new_blocks {
            frozen.extend(roots.push(tree::leaf_hash(b)));
        }
        if roots.root() != head.root {
            return false;
        }
        // Persist the new blocks + frozen nodes + head atomically before touching in-RAM
        // state, so a store failure leaves the replica exactly as it was.
        let batch = Batch {
            blocks: new_blocks
                .into_iter()
                .enumerate()
                .map(|(j, b)| (start + j as u64, b))
                .collect(),
            nodes: frozen,
            head: Some(head.clone()),
        };
        if self.store.commit(&self.feed, batch).is_err() {
            return false;
        }
        self.roots = roots;
        self.head = head;
        true
    }
}

impl Source for Replica {
    fn head(&self) -> Head {
        self.head.clone()
    }
    fn get(&self, index: usize) -> Option<Vec<u8>> {
        self.block(index)
    }
    fn proof(&self, index: usize) -> Option<Proof> {
        self.roots
            .proof(index as u64, |idx| {
                self.store.node(&self.feed, idx).ok().flatten()
            })
            .map(|siblings| Proof { siblings })
    }
    fn peaks(&self) -> Vec<(u64, Hash)> {
        self.peak_nodes()
    }
    fn held_ranges(&self) -> Vec<(u64, u64)> {
        Replica::held_ranges(self)
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
        assert_eq!(log.get(0).as_deref(), Some([0u8; 1].as_slice()));
        assert_eq!(log.get(3).as_deref(), Some([3u8; 4].as_slice()));
        assert_eq!(log.get(4), None);
    }

    #[test]
    fn with_store_reopens_a_persisted_feed_identically() {
        // A shared store outlives the log; reopening over it must rebuild the same tree,
        // head, and blocks — the property the disk backend relies on across a restart.
        let store: std::sync::Arc<dyn FeedStore> = std::sync::Arc::new(MemStore::new());
        let seed = [5u8; 32];
        let head_before = {
            let mut log = Log::with_store(Keypair::from_seed(&seed), store.clone()).unwrap();
            for i in 0..5u8 {
                log.append(vec![i; i as usize + 1]);
            }
            assert_eq!(log.len(), 5);
            log.head()
        };

        let reopened = Log::with_store(Keypair::from_seed(&seed), store).unwrap();
        assert_eq!(reopened.len(), 5, "length recovered from the store");
        assert_eq!(
            reopened.head(),
            head_before,
            "reopened head is byte-identical — the Merkle tree rebuilt exactly"
        );
        assert_eq!(reopened.get(3).as_deref(), Some([3u8; 4].as_slice()));
        // A proof from the reopened log still verifies against its head.
        let proof = reopened.proof(3).unwrap();
        assert!(verify_block(
            &reopened.public_key(),
            &reopened.head(),
            3,
            &reopened.get(3).unwrap(),
            &proof
        ));
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
                verify_block(&pk, &head, i as u64, &log.get(i).unwrap(), &proof),
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
                &log.get(i).unwrap(),
                &proof
            ));
        }
        // It still rejects a tampered block and an out-of-range index...
        let proof0 = log.proof(0).unwrap();
        assert!(!verify_block_proof(&head, 0, b"tampered", &proof0));
        assert!(!verify_block_proof(
            &head,
            99,
            &log.get(0).unwrap(),
            &proof0
        ));
        // ...but, unlike verify_block, does NOT check the head signature: a head
        // with a bad signature but the real root still passes proof-only (that's
        // the caller's responsibility to have verified once).
        let forged = Head {
            signature: Keypair::from_seed(&[0xAB; 32]).sign(b"nonsense"),
            ..head.clone()
        };
        assert!(verify_block_proof(
            &forged,
            0,
            &log.get(0).unwrap(),
            &proof0
        ));
        assert!(!verify_block(
            &log.public_key(),
            &forged,
            0,
            &log.get(0).unwrap(),
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
        assert!(!verify_block(&pk, &head, 4, &log.get(2).unwrap(), &proof));
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
                &replica.get(i).unwrap(),
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
                &replica.get(i).unwrap(),
                &proof
            ));
        }

        // A non-contiguous advance (wrong new-block count) is rejected, unchanged.
        assert!(!replica.advance(log.head(), vec![b"extra".to_vec()]));
        assert_eq!(replica.len(), 5);
    }

    #[test]
    fn replica_reopens_from_its_store() {
        // A mirror persisted in a store is restored on restart with no re-commit:
        // Replica::open rebuilds the same head + blocks + verifying proofs.
        let store: std::sync::Arc<dyn FeedStore> = std::sync::Arc::new(MemStore::new());
        let src = log_with(5);
        let pk = src.public_key();
        let head = src.head();
        let blocks: Vec<Vec<u8>> = (0..5).map(|i| src.get(i).unwrap()).collect();

        // Mirror into the store, then re-open from the same store.
        let mirror = Replica::with_store(pk, head.clone(), blocks, store.clone()).unwrap();
        assert_eq!(mirror.len(), 5);
        let reopened = Replica::open(pk, store)
            .unwrap()
            .expect("a persisted replica reopens");
        assert_eq!(reopened.len(), 5);
        assert_eq!(
            reopened.head(),
            head,
            "reopened head matches — tree rebuilt exactly"
        );
        assert_eq!(reopened.block(3).as_deref(), Some([3u8; 4].as_slice()));
        let proof = reopened.proof(3).unwrap();
        assert!(verify_block(
            &pk,
            &head,
            3,
            &reopened.get(3).unwrap(),
            &proof
        ));
    }

    #[test]
    fn replica_open_absent_feed_is_none() {
        let store: std::sync::Arc<dyn FeedStore> = std::sync::Arc::new(MemStore::new());
        let pk = Keypair::from_seed(&[0x33; 32]).public();
        assert!(Replica::open(pk, store).unwrap().is_none());
    }

    #[test]
    fn pruning_drops_the_prefix_but_keeps_the_suffix_provable() {
        // A mirror prunes to a suffix window: the pruned prefix is gone (unservable,
        // unprovable) while every retained block still serves and proves against the
        // unchanged signed head. The feed's length/shape is untouched.
        let src = log_with(20);
        let pk = src.public_key();
        let head = src.head();
        let store: std::sync::Arc<dyn FeedStore> = std::sync::Arc::new(MemStore::new());
        let blocks: Vec<Vec<u8>> = (0..20).map(|i| src.get(i).unwrap()).collect();
        let mirror = Replica::with_store(pk, head.clone(), blocks, store).unwrap();

        mirror.prune(12); // keep the tail window [12, 20)

        assert_eq!(
            mirror.len(),
            20,
            "length is unchanged — it still knows the shape"
        );
        assert_eq!(
            mirror.held_ranges(),
            vec![(12, 20)],
            "only the suffix window is held now"
        );
        for i in 0..12 {
            assert!(mirror.block(i).is_none(), "pruned block {i} is gone");
            assert!(
                Source::proof(&mirror, i).is_none(),
                "a pruned block can't be proved"
            );
        }
        for i in 12..20 {
            assert_eq!(
                mirror.block(i),
                src.get(i),
                "retained block {i} still served"
            );
            let proof = Source::proof(&mirror, i).expect("retained block still proves");
            assert!(
                verify_block(&pk, &head, i as u64, &mirror.block(i).unwrap(), &proof),
                "retained block {i} verifies against the original head"
            );
        }
        // Idempotent + monotonic: re-pruning at or below the window is a no-op for the tail.
        mirror.prune(12);
        assert_eq!(mirror.held_ranges(), vec![(12, 20)]);
    }

    #[test]
    fn sparse_replica_holds_and_serves_a_subset() {
        // A sparse replica learns a feed's shape (root + len) from the head and peaks while
        // holding no blocks, then ingests an arbitrary subset and serves/proves exactly
        // those — staying Absent for the rest. This is Phase C's receive side end to end.
        let author = log_with(20);
        let pk = author.public_key();
        let head = author.head();
        let peaks = author.peak_nodes();

        let store: std::sync::Arc<dyn FeedStore> = std::sync::Arc::new(MemStore::new());
        let mut sparse =
            Replica::sparse(pk, head.clone(), peaks, store).expect("opens from head + peaks");
        assert_eq!(
            sparse.len(),
            20,
            "knows the length without holding any block"
        );
        assert!(sparse.block(3).is_none(), "holds no blocks yet");
        assert!(sparse.proof(3).is_none(), "can't prove a block it lacks");

        // Ingest a scattered subset (spanning both peaks: 20 = 16 + 4) with proofs from
        // the author.
        for &i in &[3usize, 4, 17] {
            let block = author.get(i).unwrap();
            let proof = author.proof(i).unwrap();
            assert!(
                sparse.ingest(i as u64, block, &proof),
                "block {i} verifies and is stored"
            );
        }

        // It now serves + proves exactly those, each still verifying against the head.
        for &i in &[3usize, 4, 17] {
            assert_eq!(sparse.block(i), author.get(i), "serves ingested block {i}");
            let proof = sparse.proof(i).expect("proves an ingested block");
            assert!(
                verify_block(&pk, &head, i as u64, &sparse.block(i).unwrap(), &proof),
                "re-served proof for block {i} verifies against the signed head"
            );
        }

        // Un-ingested indices remain absent — both the block and its proof.
        for i in [0usize, 5, 19] {
            assert!(sparse.block(i).is_none(), "block {i} not ingested → absent");
            assert!(sparse.proof(i).is_none(), "no proof for un-held block {i}");
        }

        // A forged block is rejected and stores nothing.
        let real_proof = author.proof(7).unwrap();
        assert!(
            !sparse.ingest(7, b"forged".to_vec(), &real_proof),
            "wrong bytes fail verification"
        );
        assert!(sparse.block(7).is_none(), "rejected ingest stored nothing");
    }

    #[test]
    fn sparse_replica_rejects_peaks_that_dont_match_the_head() {
        // Opening sparse from peaks that don't reproduce the signed root must fail closed —
        // otherwise a lying provider could seed a holder with a tree it can't verify against.
        let author = log_with(12);
        let pk = author.public_key();
        let head = author.head();
        let mut peaks = author.peak_nodes();
        if let Some((_, hash)) = peaks.first_mut() {
            hash[0] ^= 0xff; // corrupt the largest peak
        }
        let store: std::sync::Arc<dyn FeedStore> = std::sync::Arc::new(MemStore::new());
        assert!(
            Replica::sparse(pk, head, peaks, store).is_none(),
            "peaks not reproducing the root are rejected"
        );
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
