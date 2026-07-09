//! Sans-IO feed synchronization: pull a [`feed`] from a peer, verifying every
//! block against the feed's signed head before accepting it.
//!
//! Like the DHT core, this does **no I/O**. A [`FeedDownload`] (the client)
//! emits request [`Message`]s and consumes response ones; [`serve_feed`] (the
//! server) answers a request from a local [`feed::Log`]. The `driver` pumps
//! these messages over a punched channel later; here they're pure values, so the
//! security-critical question — *can a malicious peer make us accept bad data?* —
//! is answered by a deterministic two-party message loop with no sockets.
//!
//! Trust flows from one thing the client is assumed to already know: the feed's
//! [`crypto::PublicKey`]. The head must be signed by it, and every block must
//! carry an inclusion proof that verifies against that signed head — so a server
//! that lies about a block, a head, or a length is rejected, never trusted.
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

use std::collections::HashMap;

use crypto::PublicKey;
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

/// A sync protocol message: a request from the client, or a response from the
/// server. One connection syncs one feed, so a request needs no feed id.
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
        // A server doesn't act on responses.
        Message::Head(_) | Message::Block { .. } | Message::Absent => Message::Absent,
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

    /// Verify and fold in a response. Every response has exactly two fates:
    /// verified progress, or a terminal [`SyncError`] that ends the session (the
    /// caller drops the peer). Nothing is silently ignored — an ignored response
    /// plus a re-issuing [`Self::poll_request`] would be an infinite loop.
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
            // A request where a response was expected: a protocol violation.
            Message::GetHead | Message::GetBlock { .. } => Err(SyncError::Unexpected),
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

/// Why a sync response was rejected, or a message failed to decode.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SyncError {
    /// The head's signature didn't verify against the feed's public key.
    #[error("head signature invalid")]
    BadHead,
    /// A block's inclusion proof didn't verify against the head.
    #[error("block proof invalid")]
    BadBlock,
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
        let msgs = [
            Message::GetHead,
            Message::Head(server.head()),
            Message::GetBlock { index: 3 },
            serve_feed(&Message::GetBlock { index: 2 }, &server),
            Message::Absent,
        ];
        for m in msgs {
            assert_eq!(Message::decode(&m.encode()).unwrap(), m);
        }
    }
}
