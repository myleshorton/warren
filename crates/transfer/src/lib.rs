//! Run the [`sync`] protocol over a punched [`driver::Channel`] — the adapter
//! that turns the pure, sans-IO sync state machines into a real download across
//! the network.
//!
//! [`sync`] verifies everything but does no I/O; [`driver`] reaches any peer and
//! hands back a `Channel` but knows nothing of feeds or blobs. This crate is the
//! thin seam between them: it frames each [`sync::Message`] onto the channel,
//! pumps request↔response, and supplies the *liveness* the sync docs delegate to
//! the I/O layer — a per-request timeout with a few retransmits (the channel is
//! unreliable UDP), and an idle timeout that ends a server's session when the
//! client stops asking.
//!
//! A datagram can't be large: the safe ceiling is far below UDP's 64 KiB — macOS
//! caps a datagram at 9216 bytes (`net.inet.udp.maxdgram`), and above the path
//! MTU a datagram is IP-fragmented, where a single lost IP fragment drops the
//! whole thing. But a single message — a blob chunk, a feed block with its
//! proof, a manifest — is routinely larger. The `frame` sublayer bridges that:
//! it splits an outgoing message into MTU-sized fragments (each ≤ `FRAGMENT`,
//! small enough to never be IP-fragmented) and reassembles them on the far side,
//! so a message may span many datagrams (up to [`MAX_MESSAGE`] total). The
//! `Channel` and the `sync` codec are untouched; fragmentation lives here.
//!
//! Reliability is still stop-and-wait: a request is retransmitted whole on
//! timeout, and a whole message — every fragment — is resent, not repaired
//! fragment-by-fragment. That keeps recovery simple (re-ask) and safe (the sync
//! state machines fold duplicate responses in idempotently), at the cost of
//! resending a whole message on any single lost fragment. Per-fragment
//! acknowledgement — repairing only the lost fragments, so a large transfer
//! survives a lossy link — is the next step.
//!
//! Each call borrows the channel `&mut`, so the type system enforces that one
//! channel runs a single transfer at a time: two concurrent transfers would
//! interleave datagrams and mis-correlate responses (which the sync layer would
//! reject as protocol violations).

mod frame;

use std::time::Duration;

use crypto::{Hash, PublicKey};
use driver::Channel;
use frame::Reassembler;
use sync::{BlobDownload, FeedDownload, Message, SyncError};
use thiserror::Error;
use tokio::time::{timeout, Instant};

pub use frame::MAX_MESSAGE;

/// Largest datagram we'll read into the receive buffer — UDP's theoretical
/// maximum payload on **both** IPv4 and IPv6 (65535 − 40-byte IPv6 header −
/// 8-byte UDP header; the IPv4 limit of 65507 is larger). We *send* only
/// `FRAGMENT`-sized datagrams, but read into a buffer this large so a bigger
/// datagram from a peer is never silently truncated (which would corrupt
/// reassembly) — it's reassembled and then rejected by verification if bogus.
pub const MAX_DATAGRAM: usize = 65_487;

/// Target size of a datagram we send: small enough to fit within the IPv6
/// minimum MTU (1280 − 40 − 8 = 1232), so a fragment is never IP-fragmented and
/// stays well under platform caps like macOS's 9216-byte `udp.maxdgram`. A
/// message larger than one fragment is split across several (see `frame`).
const FRAGMENT: usize = 1200;

/// Timing for a transfer over an unreliable channel.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// How long to wait for a response before retransmitting the request.
    pub request_timeout: Duration,
    /// How many times to retransmit a request before giving up.
    pub retries: usize,
    /// How long a server waits for the next request before assuming the client
    /// is done and ending the session.
    pub idle: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(2),
            retries: 4,
            idle: Duration::from_secs(10),
        }
    }
}

/// Download and verify a whole feed over `channel`, returning its blocks in
/// order. Trust is anchored in `public_key` (see [`sync`]).
pub async fn download_feed(
    channel: &mut Channel,
    public_key: PublicKey,
    cfg: &Config,
) -> Result<Vec<Vec<u8>>, TransferError> {
    let mut dl = FeedDownload::new(public_key);
    let mut wire = Wire::new(channel);
    while let Some(request) = dl.poll_request() {
        let response = exchange(&mut wire, &request, cfg).await?;
        dl.handle_response(&response)?;
    }
    Ok(dl.into_blocks())
}

/// Download and verify a whole blob over `channel`, returning its bytes. Trust
/// is anchored in the content address `id`.
pub async fn download_blob(
    channel: &mut Channel,
    id: Hash,
    cfg: &Config,
) -> Result<Vec<u8>, TransferError> {
    let mut dl = BlobDownload::new(id);
    let mut wire = Wire::new(channel);
    while let Some(request) = dl.poll_request() {
        let response = exchange(&mut wire, &request, cfg).await?;
        dl.handle_response(&response)?;
    }
    dl.reassemble().ok_or(TransferError::Incomplete)
}

/// Serve feed sync requests on `channel` from a local [`feed::Log`] until the
/// client goes idle (or the channel breaks).
pub async fn serve_feed(
    channel: &mut Channel,
    log: &feed::Log,
    cfg: &Config,
) -> Result<(), TransferError> {
    serve(channel, cfg, |request| sync::serve_feed(request, log)).await
}

/// Serve blob sync requests on `channel` from a local [`blob::Store`]. The store
/// must hold each blob's manifest under its own content address (see
/// [`sync::serve_blob`]).
pub async fn serve_blob(
    channel: &mut Channel,
    store: &blob::Store,
    cfg: &Config,
) -> Result<(), TransferError> {
    serve(channel, cfg, |request| sync::serve_blob(request, store)).await
}

/// Send `request` and return the first decodable response, retransmitting on
/// timeout up to `cfg.retries` times. A duplicate response from a retransmit is
/// harmless — the sync state machines fold duplicates in idempotently.
async fn exchange(
    wire: &mut Wire<'_>,
    request: &Message,
    cfg: &Config,
) -> Result<Message, TransferError> {
    for _ in 0..=cfg.retries {
        wire.send(request).await?;
        // Read until this attempt's window elapses, ignoring undecodable or
        // still-incomplete datagrams (corruption, strays, partial reassembly)
        // rather than retransmitting on each — otherwise a peer could trigger
        // rapid-fire resends with junk, and `request_timeout` would no longer
        // bound the retransmit rate.
        let deadline = Instant::now() + cfg.request_timeout;
        loop {
            match wire.recv(deadline).await? {
                // Accept only a response; a stray request (peer confusion, or a
                // previous session) is ignored like junk, not returned — handing
                // it to the sync client would abort as Unexpected.
                Some(message) if !message.is_request() => return Ok(message),
                Some(_) => {}  // request-type: keep waiting
                None => break, // window elapsed: retransmit
            }
        }
    }
    Err(TransferError::Timeout)
}

/// The server loop shared by [`serve_feed`]/[`serve_blob`]: read a request,
/// answer it with `respond`, send the reply; return when the client goes idle.
async fn serve(
    channel: &Channel,
    cfg: &Config,
    respond: impl Fn(&Message) -> Message,
) -> Result<(), TransferError> {
    let mut wire = Wire::new(channel);
    // Idle is measured from the last *valid* request, so a peer can't hold the
    // session open by sending undecodable junk.
    let mut deadline = Instant::now() + cfg.idle;
    loop {
        match wire.recv(deadline).await? {
            // Answer only genuine requests. A response-type message (peer
            // confusion, or a delayed packet) is ignored — replying `Absent` to
            // it would inject terminal traffic at the client. Only a valid
            // request advances the idle deadline.
            Some(request) if request.is_request() => {
                wire.send(&respond(&request)).await?;
                deadline = Instant::now() + cfg.idle;
            }
            Some(_) => {}          // response-type: ignore
            None => return Ok(()), // idle: the client has stopped asking
        }
    }
}

/// Frames sync messages onto a datagram [`Channel`]: fragments each outgoing
/// message and reassembles incoming ones (see `frame`). One `Wire` serves a
/// whole transfer or server session — stop-and-wait means a single message is in
/// flight per direction — so it holds one monotonic outbound id counter (ids let
/// the peer's reassembler follow the newest attempt) and one inbound reassembler.
struct Wire<'a> {
    channel: &'a Channel,
    next_id: u64,
    inbound: Reassembler,
    buf: Vec<u8>,
}

impl<'a> Wire<'a> {
    fn new(channel: &'a Channel) -> Self {
        Self {
            channel,
            next_id: 0,
            inbound: Reassembler::new(),
            buf: vec![0u8; MAX_DATAGRAM],
        }
    }

    /// Fragment `message` and send every fragment. A message larger than
    /// [`MAX_MESSAGE`] is refused up front as [`TransferError::MessageTooLarge`]
    /// rather than split into an unbounded number of datagrams.
    async fn send(&mut self, message: &Message) -> Result<(), TransferError> {
        let bytes = message.encode();
        if bytes.len() > MAX_MESSAGE {
            return Err(TransferError::MessageTooLarge(bytes.len()));
        }
        let id = self.next_id;
        self.next_id += 1;
        for fragment in frame::fragment(id, &bytes, FRAGMENT) {
            self.channel.send(&fragment).await?;
        }
        Ok(())
    }

    /// Read datagrams until a whole message reassembles, or `deadline` passes
    /// (`Ok(None)`). A datagram that doesn't complete a message — a fragment of
    /// one still in flight, junk, or a reassembly that fails to decode — folds in
    /// as noise and keeps the wait going; only a socket error is fatal.
    async fn recv(&mut self, deadline: Instant) -> Result<Option<Message>, TransferError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None); // window/idle over
            }
            match timeout(remaining, self.channel.recv(&mut self.buf)).await {
                Ok(Ok(n)) => {
                    if let Some(payload) = self.inbound.push(&self.buf[..n]) {
                        // A reassembled but undecodable message is junk: ignore
                        // it and keep waiting, as with a single bad datagram.
                        if let Ok(message) = Message::decode(&payload) {
                            return Ok(Some(message));
                        }
                    }
                }
                Ok(Err(e)) => return Err(TransferError::Io(e)),
                Err(_) => return Ok(None), // deadline elapsed
            }
        }
    }
}

/// Why a transfer failed.
#[derive(Debug, Error)]
pub enum TransferError {
    /// A peer's response didn't verify (see [`SyncError`]).
    #[error(transparent)]
    Sync(#[from] SyncError),
    /// A request went unanswered after all retransmits.
    #[error("peer did not respond")]
    Timeout,
    /// An encoded message exceeded [`MAX_MESSAGE`] — too large to fragment and
    /// send even across multiple datagrams (see the crate docs).
    #[error("message of {0} bytes exceeds the maximum message size")]
    MessageTooLarge(usize),
    /// The download finished but the blob couldn't be reassembled.
    #[error("blob incomplete")]
    Incomplete,
    /// The channel failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
