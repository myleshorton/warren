//! Sans-IO synchronization: pull a [`feed`] or a [`blob`] from a peer,
//! verifying everything received before accepting it.
//!
//! Like the DHT core, this does **no I/O**. A client state machine
//! ([`FeedDownload`] / [`BlobDownload`]) emits request [`Message`]s and consumes
//! response ones; a server function ([`serve_feed`] / [`serve_blob`]) answers a
//! request from a local [`feed::Log`] / [`blob::Store`]. The `driver` pumps
//! these messages over a punched channel later; here they're pure values, so the
//! security-critical question — *can a malicious peer make us accept bad data?* —
//! is answered by a deterministic two-party message loop with no sockets.
//!
//! The two downloads mirror the two trust models of the data layer:
//!
//! - a **feed** is trusted via a [`crypto::PublicKey`] the client already knows:
//!   the head must be signed by it, and every block must carry an inclusion proof
//!   that verifies against that signed head;
//! - a **blob** is trusted via its content address: the manifest must hash to the
//!   id requested, and every chunk must hash to one the manifest names.
//!
//! Either way a peer that sends anything that doesn't verify is rejected.
//!
//! ```
//! use sync::{serve_feed, FeedDownload};
//! use feed::Log;
//! use crypto::Keypair;
//!
//! // Server has a feed; client knows only its public key.
//! let mut log = Log::new(Keypair::from_seed(&[1u8; 32]));
//! log.append(b"a");
//! log.append(b"b");
//! log.append(b"c");
//!
//! let mut dl = FeedDownload::new(log.public_key());
//! // Drive to completion: request -> serve -> handle, until nothing's left.
//! while let Some(request) = dl.poll_request() {
//!     let response = serve_feed(&request, &log);
//!     dl.handle_response(&response).unwrap();
//! }
//! assert!(dl.is_complete());
//! assert_eq!(dl.into_blocks(), vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
//! ```

use std::collections::{HashMap, HashSet, VecDeque};

use blob::Manifest;
use crypto::{hash, Hash, PublicKey, HASH_LEN};
use feed::{verify_block_proof, verify_head, Head, Proof};
use thiserror::Error;
use wire::{Decoder, Encoder, WireError};

/// Upper bound on the number of blocks a [`FeedDownload`] will sync. The head's
/// length is attacker-influenced (a malicious publisher signs its own head), so
/// a client refuses a head claiming more than this — otherwise a forged huge
/// length would drive unbounded requests. Generous for real feeds, finite
/// against abuse.
pub const MAX_SYNC_BLOCKS: u64 = 1 << 20;

const KIND_GET_HEAD: u8 = 1;
const KIND_HEAD: u8 = 2;
const KIND_GET_BLOCK: u8 = 3;
const KIND_BLOCK: u8 = 4;
const KIND_ABSENT: u8 = 5;
const KIND_GET_MANIFEST: u8 = 6;
const KIND_MANIFEST: u8 = 7;
const KIND_GET_CHUNK: u8 = 8;
const KIND_CHUNK: u8 = 9;
const KIND_GET_HAVE: u8 = 10;
const KIND_HAVE: u8 = 11;
const KIND_TAIL: u8 = 12;
const KIND_GET_PEAKS: u8 = 13;
const KIND_PEAKS: u8 = 14;
const KIND_GET_FEED_HAVE: u8 = 15;
const KIND_FEED_HAVE: u8 = 16;

/// A `u64`-length Merkle tree has at most 64 peaks (one per set bit of the length),
/// so a [`Message::Peaks`] carrying more is malformed — a hard cap against a crafted
/// count over-allocating on decode.
const MAX_PEAKS: u64 = 64;

/// Upper bound on the ranges in a [`Message::FeedHave`]. A holder's window is normally
/// a few contiguous runs; a well-behaved server coalesces. The cap bounds a crafted
/// hint's allocation (the buffer bounds it further, since each range is ≥ 2 bytes).
const MAX_HAVE_RANGES: u64 = 1 << 16;

/// A sync protocol message: a request from the client, or a response from the
/// server. A session is tied to one feed, so feed requests carry no id; blob
/// requests are content-addressed and name what they want (`GetManifest`/
/// `GetChunk`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Client → server: send the feed's current signed head.
    GetHead,
    /// Client → server: a live-tail poll — "I already have `have` blocks; send the
    /// current signed head." Like [`Message::GetHead`], but signals a subscription:
    /// the server may hold the response until the feed grows past `have` (bounded by
    /// a keepalive at the I/O layer), so a subscriber blocks until there is genuinely
    /// new data rather than busy-polling.
    Tail {
        /// How many blocks the subscriber already holds (its verified length).
        have: u64,
    },
    /// Server → client: the signed head.
    Head(Head),
    /// Client → server: send block `index` with its inclusion proof.
    GetBlock {
        /// The block index requested.
        index: u64,
    },
    /// Server → client: a block and the proof that it belongs to the head.
    Block {
        /// The block's index.
        index: u64,
        /// The block bytes.
        data: Vec<u8>,
        /// Inclusion proof against the signed head.
        proof: Proof,
    },
    /// Client → server: send the blob manifest with this content address.
    GetManifest {
        /// The blob's content address (hash of its manifest).
        id: Hash,
    },
    /// Server → client: a blob manifest (verified by the client against the id
    /// it requested — content addressing needs no signature).
    Manifest(Manifest),
    /// Client → server: send the chunk with this hash.
    GetChunk {
        /// The chunk's content hash.
        hash: Hash,
    },
    /// Server → client: chunk bytes. The client derives the hash and checks it
    /// belongs to the manifest, so the hash is implicit.
    Chunk {
        /// The chunk bytes.
        data: Vec<u8>,
    },
    /// Client → server: which chunks of blob `id` do you hold? Used by a swarm
    /// download to schedule rarest-first among partial seeders.
    GetHave {
        /// The blob's content address.
        id: Hash,
    },
    /// Server → client: a bitfield over the blob's manifest — bit `i` (bit `i%8`
    /// of byte `i/8`, LSB-first) is set iff the server holds `manifest.chunks[i]`.
    /// The client interprets it against the manifest it already fetched, as a
    /// *scheduling hint*. Every chunk is still verified by hash on receipt, so an
    /// inaccurate bitfield can never corrupt the download; it can only affect
    /// availability — a bit wrongly *set* wastes a request (the chunk comes back
    /// `Absent`), a bit wrongly *cleared* keeps the client from asking this
    /// provider for a chunk it actually has.
    Have {
        /// The holdings bitfield.
        bits: Vec<u8>,
    },
    /// Client → server: send the feed's peak nodes — the O(log n) frozen tree tops a
    /// sparse subscriber needs (with the head) to open a verified [`feed::Replica`] and
    /// check the blocks it later fetches, without downloading the whole feed. Feed-scoped,
    /// so it carries no id (a session is tied to one feed).
    GetPeaks,
    /// Server → client: the feed's peak nodes as `(flat index, hash)`, largest peak first.
    /// A holder seeds its accumulator from these and verifies that they reproduce the
    /// signed head's root before trusting them (bad peaks are caught there, not here).
    Peaks {
        /// The peak nodes.
        nodes: Vec<(u64, Hash)>,
    },
    /// Client → server: which block indices of *this* feed do you hold? Feed-scoped
    /// (no id — unlike the blob-side [`Message::GetHave`]). Lets a windowed subscriber
    /// ask a peer only for blocks it actually holds instead of probing.
    GetFeedHave,
    /// Server → client: the half-open index ranges `[start, end)` the server holds,
    /// ascending. A *scheduling hint* only: every block is still verified by its proof on
    /// receipt, so an inaccurate range can waste a request (the block comes back `Absent`)
    /// or hide an available block, but can never corrupt the download.
    FeedHave {
        /// Held index ranges `[start, end)`.
        ranges: Vec<(u64, u64)>,
    },
    /// Server → client: the requested item isn't available.
    Absent,
}

impl Message {
    /// Encode the message for transfer.
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        match self {
            Message::GetHead => {
                enc.u8(KIND_GET_HEAD);
            }
            Message::Tail { have } => {
                enc.u8(KIND_TAIL);
                enc.uint(*have);
            }
            Message::Head(head) => {
                enc.u8(KIND_HEAD);
                enc.bytes(&head.encode());
            }
            Message::GetBlock { index } => {
                enc.u8(KIND_GET_BLOCK);
                enc.uint(*index);
            }
            Message::Block { index, data, proof } => {
                enc.u8(KIND_BLOCK);
                enc.uint(*index);
                enc.bytes(data);
                enc.bytes(&proof.encode());
            }
            Message::GetManifest { id } => {
                enc.u8(KIND_GET_MANIFEST);
                enc.raw(id);
            }
            Message::Manifest(manifest) => {
                enc.u8(KIND_MANIFEST);
                enc.bytes(&manifest.encode());
            }
            Message::GetChunk { hash } => {
                enc.u8(KIND_GET_CHUNK);
                enc.raw(hash);
            }
            Message::Chunk { data } => {
                enc.u8(KIND_CHUNK);
                enc.bytes(data);
            }
            Message::GetHave { id } => {
                enc.u8(KIND_GET_HAVE);
                enc.raw(id);
            }
            Message::Have { bits } => {
                enc.u8(KIND_HAVE);
                enc.bytes(bits);
            }
            Message::GetPeaks => {
                enc.u8(KIND_GET_PEAKS);
            }
            Message::Peaks { nodes } => {
                enc.u8(KIND_PEAKS);
                enc.uint(nodes.len() as u64);
                for (index, hash) in nodes {
                    enc.uint(*index);
                    enc.raw(hash);
                }
            }
            Message::GetFeedHave => {
                enc.u8(KIND_GET_FEED_HAVE);
            }
            Message::FeedHave { ranges } => {
                enc.u8(KIND_FEED_HAVE);
                enc.uint(ranges.len() as u64);
                for (start, end) in ranges {
                    enc.uint(*start);
                    enc.uint(*end);
                }
            }
            Message::Absent => {
                enc.u8(KIND_ABSENT);
            }
        }
        enc.into_vec()
    }

    /// Decode a message from bytes.
    pub fn decode(buf: &[u8]) -> Result<Message, SyncError> {
        let mut dec = Decoder::new(buf);
        let msg = match dec.u8()? {
            KIND_GET_HEAD => Message::GetHead,
            KIND_TAIL => Message::Tail { have: dec.uint()? },
            KIND_HEAD => Message::Head(Head::decode(dec.bytes()?)?),
            KIND_GET_BLOCK => Message::GetBlock { index: dec.uint()? },
            KIND_BLOCK => Message::Block {
                index: dec.uint()?,
                data: dec.bytes()?.to_vec(),
                proof: Proof::decode(dec.bytes()?)?,
            },
            KIND_GET_MANIFEST => Message::GetManifest {
                id: dec.array::<HASH_LEN>()?,
            },
            KIND_MANIFEST => Message::Manifest(Manifest::decode(dec.bytes()?)?),
            KIND_GET_CHUNK => Message::GetChunk {
                hash: dec.array::<HASH_LEN>()?,
            },
            KIND_CHUNK => Message::Chunk {
                data: dec.bytes()?.to_vec(),
            },
            KIND_GET_HAVE => Message::GetHave {
                id: dec.array::<HASH_LEN>()?,
            },
            KIND_HAVE => Message::Have {
                bits: dec.bytes()?.to_vec(),
            },
            KIND_GET_PEAKS => Message::GetPeaks,
            KIND_PEAKS => {
                let count = dec.uint()?;
                if count > MAX_PEAKS {
                    return Err(SyncError::Malformed("too many peaks"));
                }
                // Each entry is a varint index (≥ 1 byte) plus a 32-byte hash, so bound
                // the count by the buffer as well — a crafted count under the cap still
                // can't over-allocate relative to the bytes present.
                if count > dec.remaining() as u64 / (HASH_LEN as u64 + 1) {
                    return Err(SyncError::Malformed("peak count exceeds buffer"));
                }
                let mut nodes = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let index = dec.uint()?;
                    let hash = dec.array::<HASH_LEN>()?;
                    nodes.push((index, hash));
                }
                Message::Peaks { nodes }
            }
            KIND_GET_FEED_HAVE => Message::GetFeedHave,
            KIND_FEED_HAVE => {
                let count = dec.uint()?;
                if count > MAX_HAVE_RANGES {
                    return Err(SyncError::Malformed("too many ranges"));
                }
                // Each range is two varints (≥ 2 bytes total); bound by the buffer.
                if count > dec.remaining() as u64 / 2 {
                    return Err(SyncError::Malformed("range count exceeds buffer"));
                }
                let mut ranges = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let start = dec.uint()?;
                    let end = dec.uint()?;
                    ranges.push((start, end));
                }
                Message::FeedHave { ranges }
            }
            KIND_ABSENT => Message::Absent,
            _ => return Err(SyncError::Malformed("unknown message kind")),
        };
        dec.finish()?;
        Ok(msg)
    }

    /// Whether this is a client→server *request* (rather than a server→client
    /// response). The transport uses this to drop a message arriving in the
    /// wrong direction — a stray request delivered to a downloading client, or a
    /// response delivered to a server — instead of mishandling it.
    pub fn is_request(&self) -> bool {
        matches!(
            self,
            Message::GetHead
                | Message::Tail { .. }
                | Message::GetBlock { .. }
                | Message::GetManifest { .. }
                | Message::GetChunk { .. }
                | Message::GetHave { .. }
                | Message::GetPeaks
                | Message::GetFeedHave
        )
    }
}

/// Answer a sync request from a local feed. Requests the server can't satisfy
/// (an out-of-range block) get [`Message::Absent`]. A no-op-safe default for a
/// response the server has nothing to say to is also `Absent`.
pub fn serve_feed<S: feed::Source>(request: &Message, source: &S) -> Message {
    match request {
        // Both a plain head request and a live-tail poll answer with the current
        // signed head; holding a `Tail` until the feed grows is the I/O layer's job.
        Message::GetHead | Message::Tail { .. } => Message::Head(source.head()),
        Message::GetBlock { index } => {
            let index = *index;
            match usize::try_from(index)
                .ok()
                .and_then(|i| source.get(i).zip(source.proof(i)))
            {
                Some((data, proof)) => Message::Block { index, data, proof },
                None => Message::Absent,
            }
        }
        // A sparse subscriber's opening moves: the peaks (to seed a verified replica) and
        // the holder's index ranges (so it asks only for blocks this peer holds). Both are
        // served straight from the source; a block a sparse holder lacks already answers
        // `Absent` via the `get`/`proof` returning `None` above.
        Message::GetPeaks => Message::Peaks {
            nodes: source.peaks(),
        },
        Message::GetFeedHave => Message::FeedHave {
            ranges: source.held_ranges(),
        },
        // Not a feed request this server answers (a blob request, or a response).
        _ => Message::Absent,
    }
}

/// The client side of a feed sync: request the head, then each block, verifying
/// every response against the feed's public key. Drive it by alternating
/// [`FeedDownload::poll_request`] → send → receive → [`FeedDownload::handle_response`].
pub struct FeedDownload {
    public_key: PublicKey,
    head: Option<Head>,
    /// Verified blocks received so far, keyed by index (never pre-sized to the
    /// head's claimed length, so a forged length can't force a huge allocation).
    received: HashMap<u64, Vec<u8>>,
    /// Sequential request cursor; advances past blocks already received.
    cursor: u64,
    /// Blocks below this index are assumed already held (a resumed / live-tail
    /// download): never requested, never stored, never returned. 0 for a full sync.
    base: u64,
}

impl FeedDownload {
    /// Begin syncing the feed identified by `public_key` from the start.
    pub fn new(public_key: PublicKey) -> Self {
        Self::resume(public_key, 0)
    }

    /// Resume syncing from block `have`: the caller already holds (and has
    /// verified) blocks `0..have`, so this download requests, stores, and returns
    /// only `have..head.len`. Used by a live subscription that keeps a running
    /// cursor across many rounds — new blocks are transferred once, never re-fetched.
    pub fn resume(public_key: PublicKey, have: u64) -> Self {
        Self {
            public_key,
            head: None,
            received: HashMap::new(),
            cursor: have,
            base: have,
        }
    }

    /// The next request to send, or `None` when the sync is complete (or stalled
    /// awaiting nothing). Requests the head first, then missing blocks in order.
    pub fn poll_request(&mut self) -> Option<Message> {
        let Some(head) = &self.head else {
            return Some(Message::GetHead);
        };
        // Advance past blocks we already hold, then request the next missing one.
        while self.cursor < head.len && self.received.contains_key(&self.cursor) {
            self.cursor += 1;
        }
        (self.cursor < head.len).then_some(Message::GetBlock { index: self.cursor })
    }

    /// Verify and fold in a response. Almost every response has one of two
    /// fates: verified progress, or a terminal [`SyncError`] that ends the
    /// session (the caller drops the peer). The lone exception is a duplicate
    /// [`Message::Head`] once a head is already accepted — a benign no-op, since
    /// "first head wins" and re-applying it changes nothing. (It is *not*
    /// re-validated: doing so would let a peer abort a healthy download with a
    /// crafted second head — see [`SyncError::BadHead`].)
    ///
    /// So a peer *can* avoid making progress — by repeating `Head`, or simply
    /// being slow or silent. Telling "stalled" from "slow" needs a clock, which
    /// a sans-IO core doesn't have: **liveness is the I/O layer's job**, bounded
    /// by a timeout, as the driver already bounds its other operations. This
    /// core guarantees only safety — it never accepts data that doesn't verify.
    pub fn handle_response(&mut self, response: &Message) -> Result<(), SyncError> {
        match response {
            // First head wins. Once we hold a verified head, ignore later ones so
            // a peer can't abort the download by following a good head with a bad
            // one; validate (and possibly reject) only the first.
            Message::Head(_) if self.head.is_some() => Ok(()),
            Message::Head(head) => {
                if head.len > MAX_SYNC_BLOCKS {
                    return Err(SyncError::TooLong);
                }
                if !verify_head(&self.public_key, head) {
                    return Err(SyncError::BadHead);
                }
                self.head = Some(head.clone());
                Ok(())
            }
            Message::Block { index, data, proof } => {
                // The head's signature was verified once when it was accepted, so
                // check only the block's inclusion proof against it here — no need
                // to re-verify the signature for every block.
                let head = self.head.as_ref().ok_or(SyncError::Unsolicited)?;
                if !verify_block_proof(head, *index, data, proof) {
                    return Err(SyncError::BadBlock);
                }
                self.received.entry(*index).or_insert_with(|| data.clone());
                Ok(())
            }
            // The peer can't fulfill a request we made: terminal, so the caller
            // drops it (and can try another peer) rather than us re-requesting
            // forever.
            Message::Absent => Err(SyncError::Absent),
            // A request, or a blob-side response — anything a feed download never
            // expects: a protocol violation.
            _ => Err(SyncError::Unexpected),
        }
    }

    /// The synced feed's head, once received and verified.
    pub fn head(&self) -> Option<&Head> {
        self.head.as_ref()
    }

    /// Whether every block from `base` up to the head has been received and
    /// verified (for a full download `base` is 0, so this is "every block").
    pub fn is_complete(&self) -> bool {
        match &self.head {
            Some(head) => self.received.len() as u64 == head.len.saturating_sub(self.base),
            None => false,
        }
    }

    /// The verified blocks in order, from `base` to the head (all blocks for a full
    /// download; only the newly-fetched tail for a resumed one). Only meaningful
    /// once [`Self::is_complete`]; a missing block is skipped.
    pub fn into_blocks(self) -> Vec<Vec<u8>> {
        let mut received = self.received;
        let len = self.head.map(|h| h.len).unwrap_or(0);
        (self.base..len)
            .filter_map(|i| received.remove(&i))
            .collect()
    }
}

/// The verified pieces a sparse subscriber needs to build a [`feed::Replica::sparse`]:
/// the signed head, the peaks (largest first), and the window's blocks — each with the
/// inclusion proof under which it was verified. Produced by [`FeedWindow::into_window`].
#[derive(Debug, Clone)]
pub struct WindowData {
    /// The feed's signed head (already verified against the public key).
    pub head: Head,
    /// The feed's peak nodes as `(flat index, hash)`, largest peak first.
    pub peaks: Vec<(u64, Hash)>,
    /// The fetched blocks, ascending by index: `(index, bytes, proof)`. A holder ingests
    /// each into the sparse replica (which re-verifies) and can then serve them.
    pub blocks: Vec<(u64, Vec<u8>, Proof)>,
}

/// The client side of a **windowed / sparse** feed sync: fetch the head and the peaks,
/// then only a chosen set of block indices — verifying each block against the signed head
/// and retaining its proof, so the caller can seed a [`feed::Replica::sparse`] and
/// [`ingest`](feed::Replica::ingest) the window.
///
/// It differs from [`FeedDownload`] (a contiguous full/tail sync) in two ways that matter
/// for holding *part* of a feed:
///
/// - it requests an arbitrary index set, not a range from a base to the head; and
/// - a per-block [`Message::Absent`] is **not** terminal — it means *this* peer lacks that
///   block, so the index is recorded as [`missing`](FeedWindow::missing) for the caller to
///   fetch from another peer, and the download keeps going. (Absent before the head or
///   peaks is still terminal — a peer that can't answer those is unusable.)
///
/// A holdings hint ([`Message::GetFeedHave`] → [`Message::FeedHave`]) is requested up
/// front so blocks the peer doesn't hold are skipped without a wasted probe; a peer that
/// declines it (answers `Absent`) just gets probed block by block.
pub struct FeedWindow {
    public_key: PublicKey,
    head: Option<Head>,
    peaks: Option<Vec<(u64, Hash)>>,
    /// Whether the holdings hint has resolved (received, or the peer declined it).
    have_done: bool,
    /// The indices this window wants — ascending and deduped (set at construction).
    want: Vec<u64>,
    /// Verified `(bytes, proof)` for the wants received so far, keyed by index.
    received: HashMap<u64, (Vec<u8>, Proof)>,
    /// Wants this peer can't serve (out of range, outside its holdings, or `Absent`):
    /// skipped here, left for the caller to fetch elsewhere.
    missing: HashSet<u64>,
    /// Request cursor into `want`.
    cursor: usize,
    /// Suffix mode: keep the last `window` blocks. `want` is empty until the head arrives,
    /// then filled with `[len - window, len)`. `None` for an explicit index set.
    window: Option<u64>,
}

impl FeedWindow {
    /// Begin a windowed sync of `public_key`'s feed for the block indices `want` (deduped
    /// and sorted; requests follow that order). The head and peaks are fetched first, then
    /// only those wanted indices the peer holds and that are within the head's length.
    pub fn new(public_key: PublicKey, want: impl IntoIterator<Item = u64>) -> Self {
        let mut want: Vec<u64> = want.into_iter().collect();
        want.sort_unstable();
        want.dedup();
        Self {
            public_key,
            head: None,
            peaks: None,
            have_done: false,
            want,
            received: HashMap::new(),
            missing: HashSet::new(),
            cursor: 0,
            window: None,
        }
    }

    /// Begin a windowed sync that keeps the feed's **last `window` blocks**. Unlike
    /// [`new`](FeedWindow::new), the wanted indices aren't known up front — they're derived
    /// as `[len - window, len)` once the head's length arrives. `window == 0` fetches only
    /// the head and peaks (a shape-only open, holding no blocks). This is how a suffix-window
    /// mirror bootstraps against a feed whose length it doesn't yet know.
    pub fn suffix(public_key: PublicKey, window: u64) -> Self {
        Self {
            public_key,
            head: None,
            peaks: None,
            have_done: false,
            want: Vec::new(),
            received: HashMap::new(),
            missing: HashSet::new(),
            cursor: 0,
            window: Some(window),
        }
    }

    /// The next request to send, or `None` when the window is complete (or has resolved
    /// every want to received-or-missing). Order: head, peaks, holdings hint, then each
    /// still-unresolved wanted block.
    pub fn poll_request(&mut self) -> Option<Message> {
        if self.head.is_none() {
            return Some(Message::GetHead);
        }
        if self.peaks.is_none() {
            return Some(Message::GetPeaks);
        }
        if !self.have_done {
            return Some(Message::GetFeedHave);
        }
        let len = self.head.as_ref().map(|h| h.len).unwrap_or(0);
        while self.cursor < self.want.len() {
            let idx = self.want[self.cursor];
            if idx >= len || self.received.contains_key(&idx) || self.missing.contains(&idx) {
                self.cursor += 1;
            } else {
                return Some(Message::GetBlock { index: idx });
            }
        }
        None
    }

    /// Verify and fold in a response. As in [`FeedDownload::handle_response`], safety is the
    /// only guarantee (nothing that fails to verify is ever accepted); liveness is the I/O
    /// layer's job. "First head wins" and "first peaks win" — a repeat is a benign no-op and
    /// is not re-validated, so a peer can't abort the window with a crafted second one.
    pub fn handle_response(&mut self, response: &Message) -> Result<(), SyncError> {
        match response {
            // First head wins; a later one is ignored (see FeedDownload).
            Message::Head(_) if self.head.is_some() => Ok(()),
            Message::Head(head) => {
                if head.len > MAX_SYNC_BLOCKS {
                    return Err(SyncError::TooLong);
                }
                if !verify_head(&self.public_key, head) {
                    return Err(SyncError::BadHead);
                }
                // Suffix mode: now that the length is known, want the last `window` blocks.
                if let Some(window) = self.window {
                    self.want = (head.len.saturating_sub(window)..head.len).collect();
                }
                self.head = Some(head.clone());
                Ok(())
            }
            // First peaks win. They're carried as-is: their correctness is enforced where it
            // matters — when the holder seeds a replica from them and checks they reproduce
            // the signed root — so validating here would only duplicate that (and let a
            // second bad Peaks abort a healthy window).
            Message::Peaks { .. } if self.peaks.is_some() => Ok(()),
            Message::Peaks { nodes } => {
                if self.head.is_none() {
                    return Err(SyncError::Unsolicited);
                }
                self.peaks = Some(nodes.clone());
                Ok(())
            }
            // Holdings hint: mark every want outside the peer's ranges as missing, so we
            // never ask it for a block it lacks. A hint only — never re-validated.
            Message::FeedHave { ranges } => {
                for &idx in &self.want {
                    if !ranges.iter().any(|&(s, e)| idx >= s && idx < e) {
                        self.missing.insert(idx);
                    }
                }
                self.have_done = true;
                Ok(())
            }
            Message::Block { index, data, proof } => {
                // The head signature was verified once on accept; check only the block's
                // inclusion proof against it here.
                let head = self.head.as_ref().ok_or(SyncError::Unsolicited)?;
                if !verify_block_proof(head, *index, data, proof) {
                    return Err(SyncError::BadBlock);
                }
                // Keep only blocks we actually asked for; an unrequested extra is a benign
                // no-op (want is sorted, so membership is a binary search).
                if self.want.binary_search(index).is_ok() {
                    self.received
                        .entry(*index)
                        .or_insert_with(|| (data.clone(), proof.clone()));
                }
                Ok(())
            }
            // Absent is interpreted by phase: before the head or peaks it's terminal (a peer
            // that can't answer those is unusable); in the holdings-hint phase it just means
            // an older peer without `GetFeedHave` support, so fall back to probing; against a
            // block request it means this peer lacks that block — record it missing and go on.
            Message::Absent => {
                if self.head.is_none() || self.peaks.is_none() {
                    Err(SyncError::Absent)
                } else if !self.have_done {
                    self.have_done = true;
                    Ok(())
                } else {
                    if let Some(&idx) = self.want.get(self.cursor) {
                        self.missing.insert(idx);
                    }
                    Ok(())
                }
            }
            _ => Err(SyncError::Unexpected),
        }
    }

    /// The verified head, once received.
    pub fn head(&self) -> Option<&Head> {
        self.head.as_ref()
    }

    /// The peaks, once received.
    pub fn peaks(&self) -> Option<&[(u64, Hash)]> {
        self.peaks.as_deref()
    }

    /// Wanted indices this peer could not serve (outside its holdings, out of range, or
    /// answered `Absent`) — ascending, for the caller to fetch from another peer.
    pub fn missing(&self) -> Vec<u64> {
        let mut m: Vec<u64> = self.missing.iter().copied().collect();
        m.sort_unstable();
        m
    }

    /// Whether the head, peaks, and holdings hint have all resolved and every wanted index
    /// is either received, known-missing from this peer, or beyond the head's length.
    pub fn is_complete(&self) -> bool {
        let Some(head) = &self.head else {
            return false;
        };
        self.peaks.is_some()
            && self.have_done
            && self.want.iter().all(|&i| {
                i >= head.len || self.received.contains_key(&i) || self.missing.contains(&i)
            })
    }

    /// Consume the window into the pieces needed to build a sparse replica, or `None` if the
    /// head or peaks never arrived. Blocks are ascending by index; indices this peer lacked
    /// are simply absent (fetch them elsewhere and ingest separately).
    pub fn into_window(self) -> Option<WindowData> {
        let head = self.head?;
        let peaks = self.peaks?;
        let mut indices: Vec<u64> = self.received.keys().copied().collect();
        indices.sort_unstable();
        let mut received = self.received;
        let blocks = indices
            .into_iter()
            .map(|i| {
                let (data, proof) = received.remove(&i).expect("index came from the map");
                (i, data, proof)
            })
            .collect();
        Some(WindowData {
            head,
            peaks,
            blocks,
        })
    }
}

/// Answer a blob sync request from a local [`blob::Store`]. The store must hold
/// the manifest under its own content address (i.e. `store.put(manifest.encode())`)
/// for `GetManifest` to find it. Anything the store lacks — or a non-blob request
/// — gets [`Message::Absent`].
pub fn serve_blob(request: &Message, store: &blob::Store) -> Message {
    match request {
        Message::GetManifest { id } => match store.get(id).map(Manifest::decode) {
            Some(Ok(manifest)) => Message::Manifest(manifest),
            _ => Message::Absent,
        },
        Message::GetChunk { hash } => match store.get(hash) {
            Some(data) => Message::Chunk {
                data: data.to_vec(),
            },
            None => Message::Absent,
        },
        // Report holdings as a bitfield over the blob's manifest. Needs the
        // manifest to enumerate chunks; without it the server can't map its stored
        // chunks to this blob, so it answers `Absent` (a swarm client then probes
        // it optimistically rather than relying on a haveset).
        Message::GetHave { id } => match store.get(id).map(Manifest::decode) {
            Some(Ok(manifest)) => {
                let mut bits = vec![0u8; manifest.chunks.len().div_ceil(8)];
                for (i, hash) in manifest.chunks.iter().enumerate() {
                    if store.has(hash) {
                        bits[i / 8] |= 1 << (i % 8);
                    }
                }
                Message::Have { bits }
            }
            _ => Message::Absent,
        },
        _ => Message::Absent,
    }
}

/// The client side of a blob download: fetch the manifest for a known content
/// address, then each distinct chunk, verifying every one by its hash. Drive it
/// like [`FeedDownload`]: alternate [`BlobDownload::poll_request`] → send →
/// receive → [`BlobDownload::handle_response`].
pub struct BlobDownload {
    id: Hash,
    manifest: Option<Manifest>,
    /// Distinct chunk hashes still to fetch (dedup'd; a chunk repeated in the
    /// manifest is fetched once), in request order.
    queue: VecDeque<Hash>,
    /// The chunk hashes this blob is made of, for O(1) membership on receipt.
    wanted: HashSet<Hash>,
    store: blob::Store,
}

impl BlobDownload {
    /// Begin downloading the blob with content address `id`.
    pub fn new(id: Hash) -> Self {
        Self {
            id,
            manifest: None,
            queue: VecDeque::new(),
            wanted: HashSet::new(),
            store: blob::Store::new(),
        }
    }

    /// The next request to send, or `None` when the download is complete.
    /// Requests the manifest first, then each missing chunk.
    pub fn poll_request(&mut self) -> Option<Message> {
        if self.manifest.is_none() {
            return Some(Message::GetManifest { id: self.id });
        }
        // Skip chunks we've since stored (e.g. via a dedup'd duplicate), then
        // request the next one still missing.
        while let Some(front) = self.queue.front() {
            if self.store.has(front) {
                self.queue.pop_front();
            } else {
                return Some(Message::GetChunk { hash: *front });
            }
        }
        None
    }

    /// Verify and fold in a response. Content addressing means a chunk is
    /// trusted iff its hash belongs to the manifest, so the requested-vs-received
    /// hash needn't match (any valid manifest chunk is progress).
    ///
    /// As in [`FeedDownload::handle_response`], almost every response either
    /// makes verified progress or is a terminal [`SyncError`], with the same
    /// benign no-op exceptions: a duplicate [`Message::Manifest`] once one is
    /// accepted ("first manifest wins"), and an already-stored chunk. So a peer
    /// can decline to make progress by repeating those (or being slow/silent);
    /// that liveness concern is the I/O layer's, bounded by a timeout. This core
    /// guarantees only safety — it never accepts data that doesn't verify.
    pub fn handle_response(&mut self, response: &Message) -> Result<(), SyncError> {
        match response {
            // First manifest wins; ignore a later one (see FeedDownload).
            Message::Manifest(_) if self.manifest.is_some() => Ok(()),
            Message::Manifest(manifest) => {
                // Content addressing: the manifest must hash to the id we asked
                // for. That alone authenticates it — no signature needed.
                if manifest.id() != self.id {
                    return Err(SyncError::BadManifest);
                }
                self.wanted = manifest.chunks.iter().copied().collect();
                // Distinct hashes, in first-seen order, for deterministic requests.
                let mut seen = HashSet::new();
                self.queue = manifest
                    .chunks
                    .iter()
                    .filter(|h| seen.insert(**h))
                    .copied()
                    .collect();
                self.manifest = Some(manifest.clone());
                Ok(())
            }
            Message::Chunk { data } => {
                if self.manifest.is_none() {
                    return Err(SyncError::Unsolicited);
                }
                // The hash of the bytes *is* the chunk's identity: accept it iff
                // it belongs to this blob's manifest — a chunk that doesn't is a
                // peer sending us junk. (No separate verify step: `h` is the
                // content hash, so membership is the whole check.)
                let h = hash(data);
                if !self.wanted.contains(&h) {
                    return Err(SyncError::BadChunk);
                }
                // Store only if new, so a duplicate chunk is a true no-op. Insert
                // under the hash we already computed (put_hashed) rather than let
                // the store rehash the bytes.
                if !self.store.has(&h) {
                    self.store.put_hashed(h, data.clone());
                }
                Ok(())
            }
            Message::Absent => Err(SyncError::Absent),
            _ => Err(SyncError::Unexpected),
        }
    }

    /// The verified manifest, once received.
    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
    }

    /// Whether the manifest and all its chunks have been received and verified.
    pub fn is_complete(&self) -> bool {
        self.manifest.is_some() && self.wanted.iter().all(|h| self.store.has(h))
    }

    /// Reassemble the downloaded blob, or `None` if not yet complete.
    pub fn reassemble(&self) -> Option<Vec<u8>> {
        self.store.reassemble(self.manifest.as_ref()?)
    }
}

/// Why a sync response was rejected, or a message failed to decode.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SyncError {
    /// The head's signature didn't verify against the feed's public key.
    #[error("head signature invalid")]
    BadHead,
    /// A block's inclusion proof didn't verify against the head.
    #[error("block proof invalid")]
    BadBlock,
    /// A manifest's hash didn't match the content address that was requested.
    #[error("manifest content address mismatch")]
    BadManifest,
    /// A chunk didn't hash to a chunk this blob's manifest names.
    #[error("chunk not part of the blob")]
    BadChunk,
    /// The head claims more blocks than [`MAX_SYNC_BLOCKS`].
    #[error("feed length exceeds the sync limit")]
    TooLong,
    /// A block arrived before a verified head.
    #[error("block received before head")]
    Unsolicited,
    /// The peer reported it can't serve a requested item.
    #[error("peer reported the item absent")]
    Absent,
    /// A request-type message arrived where a response was expected.
    #[error("unexpected message from peer")]
    Unexpected,
    /// A field was malformed or a tag unrecognized.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// The byte codec rejected the buffer.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// An embedded feed structure (head/proof) failed to decode.
    #[error(transparent)]
    Feed(#[from] feed::LogError),
    /// An embedded blob structure (manifest) failed to decode.
    #[error(transparent)]
    Blob(#[from] blob::BlobError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Keypair;
    use feed::Log;

    fn log_with(n: usize, seed: u8) -> Log {
        let mut log = Log::new(Keypair::from_seed(&[seed; 32]));
        for i in 0..n {
            log.append(vec![i as u8; (i % 7) + 1]);
        }
        log
    }

    /// Run a client download against a server log to completion, returning the
    /// synced blocks.
    fn sync(server: &Log) -> Vec<Vec<u8>> {
        let mut dl = FeedDownload::new(server.public_key());
        let mut steps: u64 = 0;
        while let Some(request) = dl.poll_request() {
            let response = serve_feed(&request, server);
            dl.handle_response(&response).unwrap();
            steps += 1;
            assert!(steps <= MAX_SYNC_BLOCKS + 1, "sync should terminate");
        }
        assert!(dl.is_complete());
        dl.into_blocks()
    }

    #[test]
    fn syncs_a_feed_end_to_end() {
        let server = log_with(20, 0xA1);
        let expected: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8; (i % 7) + 1]).collect();
        assert_eq!(sync(&server), expected);
    }

    #[test]
    fn syncs_an_empty_feed() {
        let server = log_with(0, 0xB2);
        assert_eq!(sync(&server), Vec::<Vec<u8>>::new());
    }

    /// Run a resumed download (a live-tail round) from block `have`, returning only
    /// the newly-fetched tail.
    fn resume_sync(server: &Log, have: u64) -> Vec<Vec<u8>> {
        let mut dl = FeedDownload::resume(server.public_key(), have);
        while let Some(request) = dl.poll_request() {
            dl.handle_response(&serve_feed(&request, server)).unwrap();
        }
        assert!(dl.is_complete());
        dl.into_blocks()
    }

    #[test]
    fn resume_fetches_only_the_new_tail() {
        let server = log_with(8, 0x5A);
        // A subscriber that already holds 5 blocks fetches only 5, 6, 7 — the tail,
        // each still verified against the signed head.
        let expected: Vec<Vec<u8>> = (5..8).map(|i| vec![i as u8; (i % 7) + 1]).collect();
        assert_eq!(resume_sync(&server, 5), expected);
    }

    #[test]
    fn resume_at_or_past_head_fetches_nothing() {
        let server = log_with(4, 0x6B);
        assert_eq!(resume_sync(&server, 4), Vec::<Vec<u8>>::new());
        // A cursor claiming more than exists is a harmless no-op (append-only).
        assert_eq!(resume_sync(&server, 9), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn tail_serves_the_current_head_and_roundtrips() {
        let server = log_with(3, 0x7C);
        // A live-tail poll answers with the current signed head, like GetHead.
        assert_eq!(
            serve_feed(&Message::Tail { have: 1 }, &server),
            Message::Head(server.head())
        );
        // And it survives the wire.
        let m = Message::Tail { have: 42 };
        assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        assert!(m.is_request());
    }

    #[test]
    fn rejects_a_head_signed_by_the_wrong_key() {
        let server = log_with(3, 0xC3);
        // Client expects a different key than the one that signed the head.
        let wrong = Keypair::from_seed(&[0xEE; 32]).public();
        let mut dl = FeedDownload::new(wrong);
        let head = serve_feed(&Message::GetHead, &server);
        assert_eq!(dl.handle_response(&head), Err(SyncError::BadHead));
    }

    #[test]
    fn rejects_a_block_with_a_forged_proof() {
        let server = log_with(4, 0xD4);
        let mut dl = FeedDownload::new(server.public_key());
        dl.handle_response(&serve_feed(&Message::GetHead, &server))
            .unwrap();
        // A block whose bytes don't match its (real) proof.
        let mut bad = serve_feed(&Message::GetBlock { index: 1 }, &server);
        if let Message::Block { data, .. } = &mut bad {
            data.push(0xff);
        }
        assert_eq!(dl.handle_response(&bad), Err(SyncError::BadBlock));
    }

    #[test]
    fn rejects_an_over_long_head() {
        let server = log_with(2, 0xE5);
        let mut dl = FeedDownload::new(server.public_key());
        let mut head = server.head();
        head.len = MAX_SYNC_BLOCKS + 1;
        assert_eq!(
            dl.handle_response(&Message::Head(head)),
            Err(SyncError::TooLong)
        );
    }

    #[test]
    fn a_block_before_the_head_is_rejected() {
        let server = log_with(3, 0xF6);
        let mut dl = FeedDownload::new(server.public_key());
        let block = serve_feed(&Message::GetBlock { index: 0 }, &server);
        assert_eq!(dl.handle_response(&block), Err(SyncError::Unsolicited));
    }

    #[test]
    fn a_later_head_cannot_abort_an_in_progress_download() {
        let server = log_with(3, 0x39);
        let mut dl = FeedDownload::new(server.public_key());
        dl.handle_response(&serve_feed(&Message::GetHead, &server))
            .unwrap();
        // A subsequent invalid head (over-long, or wrong key) is ignored, not an
        // error — the peer can't abort us after a good head.
        let mut overlong = server.head();
        overlong.len = MAX_SYNC_BLOCKS + 1;
        assert_eq!(dl.handle_response(&Message::Head(overlong)), Ok(()));
        // ...and the sync still completes against the first head.
        while let Some(request) = dl.poll_request() {
            dl.handle_response(&serve_feed(&request, &server)).unwrap();
        }
        assert!(dl.is_complete());
    }

    #[test]
    fn absent_response_is_terminal() {
        let server = log_with(2, 0x4A);
        let mut dl = FeedDownload::new(server.public_key());
        dl.handle_response(&serve_feed(&Message::GetHead, &server))
            .unwrap();
        assert_eq!(dl.handle_response(&Message::Absent), Err(SyncError::Absent));
    }

    #[test]
    fn a_request_message_as_response_is_unexpected() {
        let server = log_with(2, 0x5B);
        let mut dl = FeedDownload::new(server.public_key());
        assert_eq!(
            dl.handle_response(&Message::GetHead),
            Err(SyncError::Unexpected)
        );
    }

    #[test]
    fn server_reports_absent_for_an_out_of_range_block() {
        let server = log_with(2, 0x17);
        assert_eq!(
            serve_feed(&Message::GetBlock { index: 5 }, &server),
            Message::Absent
        );
    }

    #[test]
    fn is_request_classifies_by_direction() {
        let (manifest, _) = blob::split(b"x");
        for req in [
            Message::GetHead,
            Message::GetBlock { index: 0 },
            Message::GetManifest {
                id: crypto::hash(b"i"),
            },
            Message::GetChunk {
                hash: crypto::hash(b"c"),
            },
        ] {
            assert!(req.is_request(), "{req:?} is a request");
        }
        for resp in [
            Message::Head(log_with(1, 0).head()),
            serve_feed(&Message::GetBlock { index: 0 }, &log_with(1, 0)),
            Message::Manifest(manifest),
            Message::Chunk { data: vec![1] },
            Message::Absent,
        ] {
            assert!(!resp.is_request(), "{resp:?} is a response");
        }
    }

    #[test]
    fn messages_roundtrip() {
        let server = log_with(5, 0x28);
        let (manifest, _) = blob::split(b"a blob to make a manifest from");
        let msgs = [
            Message::GetHead,
            Message::Head(server.head()),
            Message::GetBlock { index: 3 },
            serve_feed(&Message::GetBlock { index: 2 }, &server),
            Message::GetManifest {
                id: crypto::hash(b"id"),
            },
            Message::Manifest(manifest),
            Message::GetChunk {
                hash: crypto::hash(b"chunk"),
            },
            Message::Chunk {
                data: b"chunk bytes".to_vec(),
            },
            Message::GetHave {
                id: crypto::hash(b"id"),
            },
            Message::Have {
                bits: vec![0b1010_1101, 0x00, 0xff],
            },
            Message::GetPeaks,
            Message::Peaks {
                nodes: vec![(30, crypto::hash(b"p0")), (15, crypto::hash(b"p1"))],
            },
            Message::GetFeedHave,
            Message::FeedHave {
                ranges: vec![(0, 16), (18, 20)],
            },
            Message::Absent,
        ];
        for m in msgs {
            assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn decode_rejects_too_many_peaks() {
        let mut enc = Encoder::new();
        enc.u8(KIND_PEAKS);
        enc.uint(MAX_PEAKS + 1);
        assert_eq!(
            Message::decode(&enc.into_vec()),
            Err(SyncError::Malformed("too many peaks"))
        );
    }

    #[test]
    fn decode_rejects_too_many_ranges() {
        let mut enc = Encoder::new();
        enc.u8(KIND_FEED_HAVE);
        enc.uint(MAX_HAVE_RANGES + 1);
        assert_eq!(
            Message::decode(&enc.into_vec()),
            Err(SyncError::Malformed("too many ranges"))
        );
    }

    /// Drive a windowed download against a server source to completion, returning the
    /// verified window.
    fn window_sync<S: feed::Source>(server: &S, pk: PublicKey, want: Vec<u64>) -> WindowData {
        let mut w = FeedWindow::new(pk, want);
        let mut steps = 0u64;
        while let Some(request) = w.poll_request() {
            w.handle_response(&serve_feed(&request, server)).unwrap();
            steps += 1;
            assert!(steps <= MAX_SYNC_BLOCKS + 8, "window sync should terminate");
        }
        assert!(w.is_complete());
        w.into_window().unwrap()
    }

    #[test]
    fn serve_answers_peaks_and_feed_have() {
        let server = log_with(20, 0x2C);
        assert_eq!(
            serve_feed(&Message::GetPeaks, &server),
            Message::Peaks {
                nodes: server.peak_nodes()
            }
        );
        // A full log is dense, so its holdings are the single range [0, 20).
        assert_eq!(
            serve_feed(&Message::GetFeedHave, &server),
            Message::FeedHave {
                ranges: vec![(0, 20)]
            }
        );
    }

    #[test]
    fn windowed_sync_builds_a_verifying_sparse_replica() {
        use feed::{Replica, Source};
        let server = log_with(20, 0x91);
        let pk = server.public_key();
        let head = server.head();
        let want = vec![3u64, 4, 17];
        let window = window_sync(&server, pk, want.clone());

        assert_eq!(window.head, head);
        assert_eq!(
            window.blocks.iter().map(|(i, _, _)| *i).collect::<Vec<_>>(),
            want,
            "fetched exactly the requested window, ascending"
        );

        // Seed a sparse replica from the window and confirm it serves + proves each block.
        let store: std::sync::Arc<dyn feed::FeedStore> = std::sync::Arc::new(feed::MemStore::new());
        let mut replica =
            Replica::sparse(pk, window.head.clone(), window.peaks.clone(), store).unwrap();
        for (i, data, proof) in &window.blocks {
            assert!(replica.ingest(*i, data.clone(), proof), "ingest block {i}");
        }
        for &i in &want {
            assert_eq!(replica.block(i as usize), server.get(i as usize));
            let proof = Source::proof(&replica, i as usize).expect("proof for a held block");
            assert!(feed::verify_block(
                &pk,
                &head,
                i,
                &replica.block(i as usize).unwrap(),
                &proof
            ));
        }
        // A block outside the window was never fetched, so the sparse replica lacks it.
        assert!(replica.block(0).is_none());
    }

    #[test]
    fn windowed_sync_skips_blocks_a_sparse_peer_lacks() {
        use feed::Replica;
        // An author feed of 20 blocks…
        let author = log_with(20, 0xA7);
        let pk = author.public_key();
        let head = author.head();

        // …and a sparse *seeder* holding only the tail window [12, 20).
        let store: std::sync::Arc<dyn feed::FeedStore> = std::sync::Arc::new(feed::MemStore::new());
        let mut seeder = Replica::sparse(pk, head.clone(), author.peak_nodes(), store).unwrap();
        for i in 12..20u64 {
            let proof = author.proof(i as usize).unwrap();
            assert!(seeder.ingest(i, author.get(i as usize).unwrap(), &proof));
        }
        assert_eq!(
            seeder.held_ranges(),
            vec![(12, 20)],
            "the seeder reports exactly its window"
        );

        // A subscriber wants 5, 13, 18 — the holdings hint prunes 5 before any block probe.
        let mut w = FeedWindow::new(pk, [5u64, 13, 18]);
        while let Some(req) = w.poll_request() {
            w.handle_response(&serve_feed(&req, &seeder)).unwrap();
        }
        assert!(w.is_complete());
        assert_eq!(w.missing(), vec![5], "the seeder can't serve block 5");
        let window = w.into_window().unwrap();
        assert_eq!(
            window.blocks.iter().map(|(i, _, _)| *i).collect::<Vec<_>>(),
            vec![13, 18]
        );
        // Every served block still verifies against the author's signed head.
        for (i, data, proof) in &window.blocks {
            assert!(feed::verify_block(&pk, &head, *i, data, proof));
        }
    }

    #[test]
    fn a_peer_declining_the_holdings_hint_falls_back_to_probing() {
        let server = log_with(6, 0x3D);
        let pk = server.public_key();
        let mut w = FeedWindow::new(pk, [1u64, 4]);

        w.handle_response(&serve_feed(&Message::GetHead, &server))
            .unwrap();
        assert_eq!(w.poll_request(), Some(Message::GetPeaks));
        w.handle_response(&serve_feed(&Message::GetPeaks, &server))
            .unwrap();
        // The peer declines the holdings hint; that's benign, not terminal.
        assert_eq!(w.poll_request(), Some(Message::GetFeedHave));
        w.handle_response(&Message::Absent).unwrap();
        // So the window falls back to probing each wanted block directly.
        assert_eq!(w.poll_request(), Some(Message::GetBlock { index: 1 }));
        w.handle_response(&serve_feed(&Message::GetBlock { index: 1 }, &server))
            .unwrap();
        assert_eq!(w.poll_request(), Some(Message::GetBlock { index: 4 }));
        w.handle_response(&serve_feed(&Message::GetBlock { index: 4 }, &server))
            .unwrap();
        assert!(w.is_complete());
        assert!(w.missing().is_empty());
    }

    #[test]
    fn window_absent_before_the_head_is_terminal() {
        let pk = Keypair::from_seed(&[0x8E; 32]).public();
        let mut w = FeedWindow::new(pk, [0u64]);
        // A peer that doesn't even have the feed's head is unusable.
        assert_eq!(w.handle_response(&Message::Absent), Err(SyncError::Absent));
    }

    #[test]
    fn window_rejects_a_block_with_a_forged_proof() {
        let server = log_with(5, 0x77);
        let pk = server.public_key();
        let mut w = FeedWindow::new(pk, [2u64]);
        w.handle_response(&serve_feed(&Message::GetHead, &server))
            .unwrap();
        w.handle_response(&serve_feed(&Message::GetPeaks, &server))
            .unwrap();
        w.handle_response(&serve_feed(&Message::GetFeedHave, &server))
            .unwrap();
        let mut bad = serve_feed(&Message::GetBlock { index: 2 }, &server);
        if let Message::Block { data, .. } = &mut bad {
            data.push(0xff);
        }
        assert_eq!(w.handle_response(&bad), Err(SyncError::BadBlock));
    }

    /// Drive a suffix-window sync to completion, returning the window.
    fn suffix_sync(server: &Log, pk: PublicKey, window: u64) -> WindowData {
        let mut w = FeedWindow::suffix(pk, window);
        while let Some(request) = w.poll_request() {
            w.handle_response(&serve_feed(&request, server)).unwrap();
        }
        assert!(w.is_complete());
        w.into_window().unwrap()
    }

    #[test]
    fn suffix_window_fetches_the_last_n_blocks() {
        // A suffix mirror doesn't know the length up front — it derives the window from the
        // head, then fetches exactly the last N.
        let server = log_with(20, 0x64);
        let window = suffix_sync(&server, server.public_key(), 5);
        assert_eq!(window.head.len, 20);
        assert_eq!(
            window.blocks.iter().map(|(i, _, _)| *i).collect::<Vec<_>>(),
            vec![15, 16, 17, 18, 19],
            "the last five blocks"
        );
    }

    #[test]
    fn suffix_window_wider_than_the_feed_takes_all_of_it() {
        let server = log_with(3, 0x65);
        let window = suffix_sync(&server, server.public_key(), 100);
        assert_eq!(
            window.blocks.iter().map(|(i, _, _)| *i).collect::<Vec<_>>(),
            vec![0, 1, 2],
            "a window wider than the feed clamps to the whole feed"
        );
    }

    #[test]
    fn suffix_window_zero_holds_no_blocks() {
        // window == 0 is a shape-only open: head + peaks, no blocks — enough to build a
        // sparse replica that ingests later.
        let server = log_with(8, 0x66);
        let window = suffix_sync(&server, server.public_key(), 0);
        assert_eq!(window.head.len, 8);
        assert!(window.blocks.is_empty());
        assert!(!window.peaks.is_empty(), "peaks are still fetched");
    }

    /// Publish a blob into a store the server can serve: chunks plus the manifest
    /// under its own content address. Returns the store and the blob's id.
    fn blob_store_with(data: &[u8]) -> (blob::Store, Hash) {
        let mut store = blob::Store::new();
        let manifest = store.add(data);
        let id = store.put(manifest.encode());
        (store, id)
    }

    fn sync_blob(server: &blob::Store, id: Hash) -> Option<Vec<u8>> {
        let mut dl = BlobDownload::new(id);
        let mut steps: u64 = 0;
        while let Some(request) = dl.poll_request() {
            dl.handle_response(&serve_blob(&request, server)).unwrap();
            steps += 1;
            assert!(steps < 100_000, "blob sync should terminate");
        }
        assert!(dl.is_complete());
        dl.reassemble()
    }

    #[test]
    fn syncs_a_blob_end_to_end() {
        let data: Vec<u8> = (0..blob::CHUNK_SIZE * 2 + 50).map(|i| i as u8).collect();
        let (server, id) = blob_store_with(&data);
        assert_eq!(sync_blob(&server, id), Some(data));
    }

    #[test]
    fn syncs_a_blob_with_duplicate_chunks() {
        // Identical chunks dedup: the manifest lists one hash repeatedly, and the
        // download fetches it once.
        let data = vec![0x5au8; blob::CHUNK_SIZE * 3];
        let (server, id) = blob_store_with(&data);
        assert_eq!(sync_blob(&server, id), Some(data));
    }

    #[test]
    fn rejects_a_manifest_with_a_mismatched_id() {
        let (manifest, _) = blob::split(b"hello world");
        // The client is downloading a different content address.
        let mut dl = BlobDownload::new(crypto::hash(b"a different id"));
        assert_eq!(
            dl.handle_response(&Message::Manifest(manifest)),
            Err(SyncError::BadManifest)
        );
    }

    #[test]
    fn rejects_a_chunk_not_in_the_blob() {
        let (manifest, _) = blob::split(b"hello world");
        let mut dl = BlobDownload::new(manifest.id());
        dl.handle_response(&Message::Manifest(manifest)).unwrap();
        assert_eq!(
            dl.handle_response(&Message::Chunk {
                data: b"junk that is not part of the blob".to_vec()
            }),
            Err(SyncError::BadChunk)
        );
    }

    #[test]
    fn a_chunk_before_the_manifest_is_rejected() {
        let mut dl = BlobDownload::new(crypto::hash(b"x"));
        assert_eq!(
            dl.handle_response(&Message::Chunk {
                data: b"any".to_vec()
            }),
            Err(SyncError::Unsolicited)
        );
    }

    #[test]
    fn blob_server_reports_absent_for_unknown_items() {
        let (server, _id) = blob_store_with(b"present");
        let missing = crypto::hash(b"absent");
        assert_eq!(
            serve_blob(&Message::GetManifest { id: missing }, &server),
            Message::Absent
        );
        assert_eq!(
            serve_blob(&Message::GetChunk { hash: missing }, &server),
            Message::Absent
        );
        // No manifest for this blob → can't enumerate its chunks → Absent.
        assert_eq!(
            serve_blob(&Message::GetHave { id: missing }, &server),
            Message::Absent
        );
    }

    #[test]
    fn get_have_reports_a_holdings_bitfield() {
        // A blob of 10 distinct chunks; a store holding the manifest plus only the
        // even-indexed chunks reports a bitfield that matches exactly what it holds.
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob::split_with(&data, 100);
        assert_eq!(manifest.chunks.len(), 10);
        let id = manifest.id();

        let mut store = blob::Store::new();
        store.put(manifest.encode());
        for (i, chunk) in chunks.iter().enumerate() {
            if i % 2 == 0 {
                store.put(chunk.clone());
            }
        }

        let Message::Have { bits } = serve_blob(&Message::GetHave { id }, &store) else {
            panic!("a store holding the manifest should report a Have bitfield");
        };
        for (i, hash) in manifest.chunks.iter().enumerate() {
            let bit_set = bits[i / 8] & (1 << (i % 8)) != 0;
            assert_eq!(bit_set, store.has(hash), "bitfield disagrees at chunk {i}");
        }
        // The partial store genuinely holds some and lacks some.
        assert!(store.has(&manifest.chunks[0]) && !store.has(&manifest.chunks[1]));
    }
}
