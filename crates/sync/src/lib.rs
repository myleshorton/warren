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

/// A sync protocol message: a request from the client, or a response from the
/// server. A session is tied to one feed, so feed requests carry no id; blob
/// requests are content-addressed and name what they want (`GetManifest`/
/// `GetChunk`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Client → server: send the feed's current signed head.
    GetHead,
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
            KIND_ABSENT => Message::Absent,
            _ => return Err(SyncError::Malformed("unknown message kind")),
        };
        dec.finish()?;
        Ok(msg)
    }
}

/// Answer a sync request from a local feed. Requests the server can't satisfy
/// (an out-of-range block) get [`Message::Absent`]. A no-op-safe default for a
/// response the server has nothing to say to is also `Absent`.
pub fn serve_feed(request: &Message, log: &feed::Log) -> Message {
    match request {
        Message::GetHead => Message::Head(log.head()),
        Message::GetBlock { index } => {
            let index = *index;
            match usize::try_from(index)
                .ok()
                .and_then(|i| log.get(i).map(<[u8]>::to_vec).zip(log.proof(i)))
            {
                Some((data, proof)) => Message::Block { index, data, proof },
                None => Message::Absent,
            }
        }
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
}

impl FeedDownload {
    /// Begin syncing the feed identified by `public_key`.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            head: None,
            received: HashMap::new(),
            cursor: 0,
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

    /// Whether every block up to the head has been received and verified.
    pub fn is_complete(&self) -> bool {
        match &self.head {
            Some(head) => self.received.len() as u64 == head.len,
            None => false,
        }
    }

    /// The verified blocks in order. Only meaningful once [`Self::is_complete`];
    /// a missing block is skipped (so a partial download yields what it has).
    pub fn into_blocks(self) -> Vec<Vec<u8>> {
        let mut received = self.received;
        let len = self.head.map(|h| h.len).unwrap_or(0);
        (0..len).filter_map(|i| received.remove(&i)).collect()
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

    /// Verify and fold in a response. Like [`FeedDownload::handle_response`],
    /// every response makes verified progress or is a terminal [`SyncError`];
    /// content addressing means a chunk is trusted iff its hash belongs to the
    /// manifest, so the requested-vs-received hash needn't match (any valid
    /// manifest chunk is progress).
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
            Message::Absent,
        ];
        for m in msgs {
            assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
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
    }
}
