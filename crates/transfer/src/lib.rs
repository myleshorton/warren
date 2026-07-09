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
//! Reliability is **selective repeat**. A tiny request (one fragment) is still
//! retransmitted whole when the response goes silent. But a large response is
//! repaired per fragment: when the client's reassembly stalls, it sends a
//! `frame` NACK naming the fragment indices it's still missing, and the server
//! resends only those — so a single lost fragment costs one small datagram to
//! recover, not a resend of the whole message. The client keeps repairing as
//! long as it makes progress and gives up only after `retries` intervals with
//! none (the liveness bound the sync docs delegate to this layer). Duplicate or
//! reordered fragments are still folded in idempotently, so repair is safe.
//!
//! Runs over any [`Link`] (a datagram send/recv seam); [`driver::Channel`] is the
//! real one, and a lossy in-memory `Link` lets the repair loop be tested under
//! deterministic loss.
//!
//! Each call borrows the channel `&mut`, so the type system enforces that one
//! channel runs a single transfer at a time: two concurrent transfers would
//! interleave datagrams and mis-correlate responses (which the sync layer would
//! reject as protocol violations).

mod frame;

use std::collections::HashSet;
use std::io;
use std::time::Duration;

use crypto::{Hash, PublicKey};
use driver::Channel;
use frame::{Packet, Reassembler};
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

/// A datagram link a transfer runs over: send and receive whole datagrams to a
/// single connected peer. [`driver::Channel`] is the real one; a test supplies a
/// lossy in-memory link to exercise repair deterministically.
///
/// `async fn` in a trait is fine here: the only callers spawning these futures do
/// so on concrete types (a real `Channel`), whose futures are `Send`, so there's
/// no generic `Send` bound to express.
#[allow(async_fn_in_trait)]
pub trait Link {
    /// Send one datagram to the peer, returning the number of bytes sent.
    async fn send(&self, data: &[u8]) -> io::Result<usize>;
    /// Receive one datagram from the peer into `buf`, returning its length.
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
}

impl Link for Channel {
    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        Channel::send(self, data).await
    }
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        Channel::recv(self, buf).await
    }
}

/// Timing for a transfer over an unreliable channel.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// How long the client waits for fragment progress before acting: NACKing the
    /// gaps of a partial response, or retransmitting the request if nothing has
    /// arrived at all.
    pub request_timeout: Duration,
    /// How many consecutive intervals with *no* progress the client tolerates
    /// before giving up (the liveness bound). Repair that keeps making progress
    /// never trips it.
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
pub async fn download_feed<L: Link>(
    channel: &mut L,
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
pub async fn download_blob<L: Link>(
    channel: &mut L,
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
pub async fn serve_feed<L: Link>(
    channel: &mut L,
    log: &feed::Log,
    cfg: &Config,
) -> Result<(), TransferError> {
    serve(channel, cfg, |request| sync::serve_feed(request, log)).await
}

/// Serve blob sync requests on `channel` from a local [`blob::Store`]. The store
/// must hold each blob's manifest under its own content address (see
/// [`sync::serve_blob`]).
pub async fn serve_blob<L: Link>(
    channel: &mut L,
    store: &blob::Store,
    cfg: &Config,
) -> Result<(), TransferError> {
    serve(channel, cfg, |request| sync::serve_blob(request, store)).await
}

/// Send `request` and return the verified response, repairing losses as it goes.
/// Each interval: if the response completed, return it; otherwise NACK the
/// missing fragments (or, if nothing arrived at all, retransmit the request).
/// Gives up only after `cfg.retries` intervals with no progress — repair that
/// keeps advancing runs indefinitely. A duplicate response from a retransmit is
/// harmless: the sync state machines fold duplicates in idempotently.
async fn exchange<L: Link>(
    wire: &mut Wire<'_, L>,
    request: &Message,
    cfg: &Config,
) -> Result<Message, TransferError> {
    wire.send(request).await?;
    let mut stalls = 0;
    loop {
        let progress_from = wire.received();
        let deadline = Instant::now() + cfg.request_timeout;
        match wire.recv(deadline).await? {
            // The response completed and verified. A stray request-type message
            // or a NACK (the client doesn't serve those) is ignored — handing a
            // request to the sync client would abort it as Unexpected.
            Some(Recv::Message(message)) if !message.is_request() => return Ok(message),
            Some(_) => continue,
            None => {
                // Interval elapsed without completing. Repair: NACK the gaps of a
                // partial response, or re-ask if nothing has arrived at all.
                match wire.missing() {
                    Some(missing) => wire.nack(missing.id, &missing.indices).await?,
                    None => wire.send(request).await?,
                }
                // Count only intervals that made no progress toward the response;
                // a lossy-but-advancing transfer keeps its budget.
                if wire.received() > progress_from {
                    stalls = 0;
                } else {
                    stalls += 1;
                    if stalls > cfg.retries {
                        return Err(TransferError::Timeout);
                    }
                }
            }
        }
    }
}

/// The server loop shared by [`serve_feed`]/[`serve_blob`]: read a request,
/// answer it with `respond`, and honor NACKs by resending the missing fragments
/// of that reply; return when the client goes idle.
async fn serve<L: Link>(
    channel: &L,
    cfg: &Config,
    respond: impl Fn(&Message) -> Message,
) -> Result<(), TransferError> {
    let mut wire = Wire::new(channel);
    // Idle is measured from the last *valid* activity, so a peer can't hold the
    // session open by sending undecodable junk.
    let mut deadline = Instant::now() + cfg.idle;
    loop {
        match wire.recv(deadline).await? {
            // Answer only genuine requests. A response-type message (peer
            // confusion, or a delayed packet) is ignored — replying `Absent` to
            // it would inject terminal traffic at the client.
            Some(Recv::Message(request)) if request.is_request() => {
                wire.send(&respond(&request)).await?;
                deadline = Instant::now() + cfg.idle;
            }
            Some(Recv::Message(_)) => {} // response-type: ignore
            // The client is missing fragments of the reply we last sent: resend
            // just those. Repair is client activity, so it holds the session open.
            Some(Recv::Nack { id, indices }) => {
                wire.resend(id, &indices).await?;
                deadline = Instant::now() + cfg.idle;
            }
            None => return Ok(()), // idle: the client has stopped asking
        }
    }
}

/// What [`Wire::recv`] surfaced: a completed, decoded message, or a peer's NACK
/// asking us to resend fragments.
enum Recv {
    /// A whole message reassembled and decoded.
    Message(Message),
    /// The peer is missing the listed fragment indices of message `id`.
    Nack {
        /// The message whose fragments the peer wants resent.
        id: u64,
        /// The missing indices to resend.
        indices: Vec<u64>,
    },
}

/// Frames sync messages onto a datagram [`Link`]: fragments each outgoing message
/// (remembering the last one, to honor a NACK), reassembles incoming ones, and
/// carries NACKs for selective repair (see `frame`). One `Wire` serves a whole
/// transfer or server session — a single message is in flight per direction — so
/// it holds one monotonic outbound id counter (ids let the peer's reassembler
/// follow the newest attempt) and one inbound reassembler.
struct Wire<'a, L: Link> {
    link: &'a L,
    next_id: u64,
    inbound: Reassembler,
    buf: Vec<u8>,
    /// The most recently sent message (id + encoded bytes), kept so a NACK for it
    /// can be answered by resending just the requested fragments.
    last_sent: Option<(u64, Vec<u8>)>,
}

impl<'a, L: Link> Wire<'a, L> {
    fn new(link: &'a L) -> Self {
        Self {
            link,
            next_id: 0,
            inbound: Reassembler::new(),
            buf: vec![0u8; MAX_DATAGRAM],
            last_sent: None,
        }
    }

    /// Fragment `message`, send every fragment, and remember it for repair. A
    /// message larger than [`MAX_MESSAGE`] is refused up front as
    /// [`TransferError::MessageTooLarge`] rather than split into an unbounded
    /// number of datagrams.
    async fn send(&mut self, message: &Message) -> Result<(), TransferError> {
        let bytes = message.encode();
        if bytes.len() > MAX_MESSAGE {
            return Err(TransferError::MessageTooLarge(bytes.len()));
        }
        let id = self.next_id;
        self.next_id += 1;
        for fragment in frame::fragment(id, &bytes, FRAGMENT) {
            self.link.send(&fragment).await?;
        }
        self.last_sent = Some((id, bytes));
        Ok(())
    }

    /// Resend the requested fragments of the last message sent, if the NACK is
    /// for it (one for a superseded message is ignored). Only the requested
    /// fragments are rebuilt; indices past the message's fragment count are
    /// naturally skipped, so a NACK can't make us send more than the message.
    async fn resend(&self, id: u64, indices: &[u64]) -> Result<(), TransferError> {
        // Build just the requested fragments, releasing the borrow of `last_sent`
        // before awaiting the sends.
        let to_send: Vec<Vec<u8>> = {
            let Some((last_id, bytes)) = &self.last_sent else {
                return Ok(());
            };
            if *last_id != id {
                return Ok(());
            }
            let want: HashSet<u64> = indices.iter().copied().collect();
            frame::fragment(*last_id, bytes, FRAGMENT)
                .enumerate()
                .filter(|(i, _)| want.contains(&(*i as u64)))
                .map(|(_, fragment)| fragment)
                .collect()
        };
        for fragment in &to_send {
            self.link.send(fragment).await?;
        }
        Ok(())
    }

    /// NACK (a bounded batch of) the missing fragments of message `id`. Capped at
    /// [`frame::NACK_MAX_INDICES`] so the NACK fits one datagram; the caller
    /// re-NACKs for any remainder on the next interval.
    async fn nack(&self, id: u64, indices: &[u64]) -> Result<(), TransferError> {
        let batch = &indices[..indices.len().min(frame::NACK_MAX_INDICES)];
        self.link.send(&frame::nack_datagram(id, batch)).await?;
        Ok(())
    }

    /// How many fragments of the in-progress message have arrived — lets the
    /// driver tell whether an interval made repair progress.
    fn received(&self) -> usize {
        self.inbound.received()
    }

    /// The fragments still missing from the in-progress message, if any.
    fn missing(&self) -> Option<frame::Missing> {
        self.inbound.missing()
    }

    /// Read datagrams until a message reassembles and decodes, a NACK arrives, or
    /// `deadline` passes (`Ok(None)`). A datagram that does none of these — a
    /// fragment of a message still in flight, junk, or a reassembly that fails to
    /// decode — folds in as noise and keeps the wait going; only a socket error
    /// is fatal.
    async fn recv(&mut self, deadline: Instant) -> Result<Option<Recv>, TransferError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None); // window/idle over
            }
            match timeout(remaining, self.link.recv(&mut self.buf)).await {
                Ok(Ok(n)) => match Packet::decode(&self.buf[..n]) {
                    Some(Packet::Data {
                        id,
                        index,
                        count,
                        payload,
                    }) => {
                        if let Some((mid, bytes)) =
                            self.inbound.push_data(id, index, count, &payload)
                        {
                            // Commit the id only once the payload decodes: a
                            // reassembled but undecodable message is junk
                            // (corruption or a hostile peer), so we ignore it and
                            // — crucially — don't advance the watermark, or a
                            // bogus id would wedge every later message.
                            if let Ok(message) = Message::decode(&bytes) {
                                self.inbound.accept(mid);
                                return Ok(Some(Recv::Message(message)));
                            }
                        }
                    }
                    Some(Packet::Nack { id, indices }) => {
                        return Ok(Some(Recv::Nack { id, indices }))
                    }
                    None => {} // junk: ignore
                },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Keypair;
    use feed::Log;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{mpsc, Mutex};

    /// An in-memory [`Link`] that drops selected datagrams, so the repair loop can
    /// be driven under deterministic loss. `drop` names the indices of *this
    /// link's own sends* to silently discard.
    struct LossyLink {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        sent: AtomicUsize,
        drop: HashSet<usize>,
    }

    impl Link for LossyLink {
        async fn send(&self, data: &[u8]) -> io::Result<usize> {
            let n = self.sent.fetch_add(1, Ordering::SeqCst);
            if !self.drop.contains(&n) {
                let _ = self.tx.send(data.to_vec()); // peer gone: drop, like a dead socket
            }
            Ok(data.len())
        }
        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let datagram = self.rx.lock().await.recv().await;
            match datagram {
                Some(d) => {
                    let n = d.len().min(buf.len());
                    buf[..n].copy_from_slice(&d[..n]);
                    Ok(n)
                }
                None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "link closed")),
            }
        }
    }

    /// A cross-wired pair of lossy links: (client, server). `server_drops` names
    /// the server sends (data fragments) to lose on their first transmission.
    fn lossy_pair(client_drops: &[usize], server_drops: &[usize]) -> (LossyLink, LossyLink) {
        let (to_server, at_server) = mpsc::unbounded_channel();
        let (to_client, at_client) = mpsc::unbounded_channel();
        let client = LossyLink {
            tx: to_server,
            rx: Mutex::new(at_client),
            sent: AtomicUsize::new(0),
            drop: client_drops.iter().copied().collect(),
        };
        let server = LossyLink {
            tx: to_client,
            rx: Mutex::new(at_server),
            sent: AtomicUsize::new(0),
            drop: server_drops.iter().copied().collect(),
        };
        (client, server)
    }

    fn fast_cfg() -> Config {
        Config {
            request_timeout: Duration::from_millis(50),
            retries: 50,
            idle: Duration::from_millis(200),
        }
    }

    #[tokio::test]
    async fn selective_repeat_recovers_a_lossy_feed_download() {
        // A feed whose blocks are large enough to fragment. The server loses
        // several of its response fragments on first send; the client NACKs the
        // gaps and the server repairs them, so the download still completes and
        // verifies — without the client ever re-requesting a whole block.
        let mut log = Log::new(Keypair::from_seed(&[7u8; 32]));
        let expected: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 30_000]).collect();
        for block in &expected {
            log.append(block.clone());
        }
        let public_key = log.public_key();

        // Drop a scattered handful of the server's data fragments (the head reply
        // is a single fragment, index 0; the rest are big block replies).
        let (mut client, mut server) = lossy_pair(&[], &[3, 5, 8, 13, 21]);
        let cfg = fast_cfg();

        let (served, downloaded) = tokio::join!(
            serve_feed(&mut server, &log, &cfg),
            download_feed(&mut client, public_key, &cfg),
        );
        served.expect("server ends cleanly on idle");
        assert_eq!(downloaded.expect("download verifies"), expected);
    }

    #[tokio::test]
    async fn a_lossless_link_needs_no_repair() {
        // Sanity: with no drops the same transfer completes (exercises the Link
        // abstraction and the happy path off a real socket).
        let mut log = Log::new(Keypair::from_seed(&[8u8; 32]));
        let expected: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 5_000]).collect();
        for block in &expected {
            log.append(block.clone());
        }
        let public_key = log.public_key();

        let (mut client, mut server) = lossy_pair(&[], &[]);
        let cfg = fast_cfg();
        let (_served, downloaded) = tokio::join!(
            serve_feed(&mut server, &log, &cfg),
            download_feed(&mut client, public_key, &cfg),
        );
        assert_eq!(downloaded.expect("download verifies"), expected);
    }
}
