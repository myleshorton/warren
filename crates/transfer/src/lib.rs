//! Run the [`sync`] protocol over a punched [`driver::Channel`] — the adapter
//! that turns the pure, sans-IO sync state machines into a real download across
//! the network.
//!
//! [`sync`] verifies everything but does no I/O; [`driver`] reaches any peer and
//! hands back a `Channel` but knows nothing of feeds or blobs. This crate is the
//! thin seam between them: it frames each [`sync::Message`] as one datagram on
//! the channel, pumps request↔response, and supplies the *liveness* the sync
//! docs delegate to the I/O layer — a per-request timeout with a few
//! retransmits (the channel is unreliable UDP), and an idle timeout that ends a
//! server's session when the client stops asking.
//!
//! Because the channel is datagram UDP, one message must fit in one datagram
//! (≤ [`MAX_DATAGRAM`]); feeds/blobs whose blocks or chunks approach the UDP
//! limit need smaller blocks/chunks (a stream/fragmentation transport that
//! lifts this is future work). Retransmits can duplicate a request, but the sync
//! state machines treat duplicate responses as idempotent no-ops, so stop-and-
//! wait reliability is safe here.
//!
//! Each call borrows the channel `&mut`, so the type system enforces that one
//! channel runs a single transfer at a time: two concurrent transfers would
//! interleave datagrams and mis-correlate responses (which the sync layer would
//! reject as protocol violations).

use std::time::Duration;

use crypto::{Hash, PublicKey};
use driver::Channel;
use sync::{BlobDownload, FeedDownload, Message, SyncError};
use thiserror::Error;
use tokio::time::{timeout, Instant};

/// Largest datagram exchanged — the maximum UDP payload for IPv4
/// (65535 − 20-byte IP − 8-byte UDP headers). A single encoded [`sync::Message`]
/// must fit within this, so a feed block or blob chunk (plus wire overhead) has
/// to stay under it; a message that doesn't is a [`TransferError::MessageTooLarge`]
/// rather than an opaque socket error.
pub const MAX_DATAGRAM: usize = 65_507;

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
    let mut buf = vec![0u8; MAX_DATAGRAM];
    while let Some(request) = dl.poll_request() {
        let response = exchange(channel, &request, &mut buf, cfg).await?;
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
    let mut buf = vec![0u8; MAX_DATAGRAM];
    while let Some(request) = dl.poll_request() {
        let response = exchange(channel, &request, &mut buf, cfg).await?;
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
    channel: &Channel,
    request: &Message,
    buf: &mut [u8],
    cfg: &Config,
) -> Result<Message, TransferError> {
    let bytes = encode_bounded(request)?;
    for _ in 0..=cfg.retries {
        channel.send(&bytes).await?;
        match timeout(cfg.request_timeout, channel.recv(buf)).await {
            Ok(Ok(n)) => {
                // A datagram that doesn't decode (corruption, a stray packet) is
                // treated like a lost round: retransmit and keep waiting.
                if let Ok(message) = Message::decode(&buf[..n]) {
                    return Ok(message);
                }
            }
            Ok(Err(e)) => return Err(TransferError::Io(e)),
            Err(_) => {} // timed out: retransmit
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
    let mut buf = vec![0u8; MAX_DATAGRAM];
    // Idle is measured from the last *valid* request, so a peer can't hold the
    // session open by sending undecodable junk.
    let mut deadline = Instant::now() + cfg.idle;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(()); // idle: the client has stopped asking
        }
        match timeout(remaining, channel.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Ok(request) = Message::decode(&buf[..n]) {
                    channel.send(&encode_bounded(&respond(&request))?).await?;
                    deadline = Instant::now() + cfg.idle;
                }
                // Undecodable datagrams are ignored and do not extend the idle
                // deadline.
            }
            Ok(Err(e)) => return Err(TransferError::Io(e)),
            Err(_) => return Ok(()),
        }
    }
}

/// Encode a message, erroring if it wouldn't fit in one datagram — so an
/// oversize block/chunk surfaces as [`TransferError::MessageTooLarge`] rather
/// than an opaque socket error.
fn encode_bounded(message: &Message) -> Result<Vec<u8>, TransferError> {
    let bytes = message.encode();
    if bytes.len() > MAX_DATAGRAM {
        return Err(TransferError::MessageTooLarge(bytes.len()));
    }
    Ok(bytes)
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
    /// An encoded message exceeded [`MAX_DATAGRAM`] and can't be sent in one
    /// datagram (a block/chunk too large for this transport — see the crate docs).
    #[error("message of {0} bytes exceeds the datagram limit")]
    MessageTooLarge(usize),
    /// The download finished but the blob couldn't be reassembled.
    #[error("blob incomplete")]
    Incomplete,
    /// The channel failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
