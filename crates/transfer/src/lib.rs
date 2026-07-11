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

mod congestion;
mod frame;
mod plan;

use std::collections::{HashMap, HashSet};
use std::io;
use std::time::Duration;

use blob::Manifest;
use congestion::{Congestion, Rtt};
use crypto::{Hash, PublicKey};
use driver::Channel;
use frame::{Packet, Reassembler};
use plan::{Holdings, Plan, Selection};
use sync::{BlobDownload, FeedDownload, Message, SyncError};
use thiserror::Error;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Instant};

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

/// Smallest pause the pacer bothers to take. Sub-millisecond sleeps are below
/// the timer's resolution, so instead of sleeping per fragment the pacer
/// accumulates the target inter-fragment interval and pauses once it reaches
/// this — bursting a few fragments between pauses on a short-RTT path, spacing
/// them out on a long one.
const MIN_PACING_SLEEP: Duration = Duration::from_millis(1);

/// How many chunks a swarm provider is handed at once before it comes back for
/// more. Small on purpose: most of the work stays in the shared pool so whichever
/// provider frees up next can pick it up (work-stealing), rather than being
/// hoarded behind a slow provider.
const STEAL_BATCH: usize = 4;

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
    /// Assumed round-trip time before the path is measured. The sender paces a
    /// window's worth of fragments across one (measured, then smoothed) RTT, so
    /// this only governs the very first reply; it's refined from the first clean
    /// request→reply→request round trip onward.
    ///
    /// The RTT used for pacing is capped at [`request_timeout`](Self::request_timeout)
    /// (see the pacer), which bounds any single pacing pause below that interval —
    /// so a pause can't be mistaken for a stall, even if a peer inflates the
    /// estimate. Best kept well below the timeout regardless (that headroom is the
    /// safety margin); the default — 100 ms against a 2 s timeout — has plenty.
    pub initial_rtt: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(2),
            retries: 4,
            idle: Duration::from_secs(10),
            initial_rtt: Duration::from_millis(100),
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
    let mut wire = Wire::new(
        channel,
        cfg.initial_rtt,
        cfg.request_timeout,
        Cursor::default(),
    );
    while let Some(request) = dl.poll_request() {
        let response = exchange(&mut wire, &request, cfg).await?;
        dl.handle_response(&response)?;
    }
    Ok(dl.into_blocks())
}

/// Subscribe to a feed and deliver its blocks **as they are appended**, over a
/// persistent `channel` against a peer serving [`serve_feed_tail`]. Each round:
/// poll the head (the server holds this until the feed grows past our cursor),
/// fetch `from..head.len` (every block verified against the signed head), deliver
/// the new tail via `on_block`, advance the cursor, repeat. The tail is
/// transferred once — never re-fetched. Returns only on a channel error; a live
/// subscription otherwise runs until the future is dropped/aborted. `from` is how
/// many blocks the caller already has (0 to tail from the start).
pub async fn subscribe_feed<L, F>(
    channel: &mut L,
    public_key: PublicKey,
    mut from: u64,
    cfg: &Config,
    mut on_block: F,
) -> Result<(), TransferError>
where
    L: Link,
    F: FnMut(u64, Vec<u8>),
{
    let mut wire = Wire::new(
        channel,
        cfg.initial_rtt,
        cfg.request_timeout,
        Cursor::default(),
    );
    loop {
        // Poll for the head — the server holds this until there are new blocks.
        let head = exchange(&mut wire, &Message::Tail { have: from }, cfg).await?;
        let mut dl = FeedDownload::resume(public_key, from);
        dl.handle_response(&head)?;
        while let Some(request) = dl.poll_request() {
            let response = exchange(&mut wire, &request, cfg).await?;
            dl.handle_response(&response)?;
        }
        let next = dl.head().map(|h| h.len).unwrap_or(from);
        for (offset, block) in dl.into_blocks().into_iter().enumerate() {
            on_block(from + offset as u64, block);
        }
        from = next;
    }
}

/// Download and verify a whole blob over `channel`, returning its bytes. Trust
/// is anchored in the content address `id`.
pub async fn download_blob<L: Link>(
    channel: &mut L,
    id: Hash,
    cfg: &Config,
) -> Result<Vec<u8>, TransferError> {
    let mut dl = BlobDownload::new(id);
    let mut wire = Wire::new(
        channel,
        cfg.initial_rtt,
        cfg.request_timeout,
        Cursor::default(),
    );
    while let Some(request) = dl.poll_request() {
        let response = exchange(&mut wire, &request, cfg).await?;
        dl.handle_response(&response)?;
    }
    dl.reassemble().ok_or(TransferError::Incomplete)
}

/// One provider's result for a round of chunk fetches.
struct ChunkOutcome {
    /// Chunks fetched and verified this round.
    fetched: Vec<(Hash, Vec<u8>)>,
    /// Whether the provider is still usable; a channel error or timeout retires it.
    alive: bool,
}

/// The per-channel session state a swarm carries across rounds: the next
/// outbound message id and the inbound accepted-watermark. Recreating a `Wire`
/// each round (a fresh [`frame::Reassembler`]) would reset both — replaying ids
/// the server drops as stale, and losing straggler protection on the response
/// side — so the driver threads a `Cursor` through each provider's fetches.
#[derive(Default, Clone, Copy)]
struct Cursor {
    next_id: u64,
    accepted: Option<u64>,
}

/// A provider in a swarm download: its channel, the session `Cursor` carried
/// across rounds, and what it advertised holding (learned once up front, so
/// chunks are assigned to providers that have them — see [`Holdings`]).
struct Provider {
    channel: Channel,
    cursor: Cursor,
    holds: Holdings,
}

/// Download and verify a blob from **several** providers at once, returning its
/// bytes. A chunk is content-addressed, so any provider holding it is
/// interchangeable and each is verified by its hash — a provider can neither
/// corrupt the blob nor be trusted beyond the bytes it proves. Chunks are
/// scheduled **rarest-first**, best for a partial-seeder swarm's health. For
/// playback order instead, see [`download_blob_stream`].
pub async fn download_blob_swarm(
    channels: Vec<Channel>,
    id: Hash,
    cfg: &Config,
) -> Result<Vec<u8>, TransferError> {
    // Rarest-first; no incremental delivery needed, so reassemble at the end.
    let plan = run_swarm(
        channels,
        id,
        cfg,
        Selection::RarestFirst,
        |_index, _bytes| {},
    )
    .await?;
    plan.reassemble().ok_or(TransferError::Incomplete)
}

/// Stream a blob from several providers for **playback**, with **bounded memory**:
/// only chunks within a `window`-sized window ahead of the playback frontier are
/// fetched (in playback order) — nothing further ahead, so a slow chunk can't make
/// providers race ahead and buffer the whole file — and each is handed to
/// `on_chunk(index, bytes)` **in playback order** (indices `0..N`, strictly) as it
/// becomes contiguously available, then freed. So a player can start before the
/// whole blob arrives, and memory stays bounded to roughly `window` chunks rather
/// than the whole blob. `window` is clamped to at least 1. Every chunk is still
/// verified by its hash before delivery. Returns [`TransferError::Incomplete`] if
/// the swarm can't supply the whole blob — the caller will have received a
/// contiguous prefix.
pub async fn download_blob_stream<F>(
    channels: Vec<Channel>,
    id: Hash,
    cfg: &Config,
    window: usize,
    on_chunk: F,
) -> Result<(), TransferError>
where
    F: FnMut(usize, &[u8]),
{
    // A zero window could never fetch even the frontier chunk (nothing would be
    // in range), so it would stall immediately; treat it as at least one.
    let window = window.max(1);
    let plan = run_swarm(channels, id, cfg, Selection::Streaming { window }, on_chunk).await?;
    // Streaming drops chunks as it delivers them, so completion is "everything
    // delivered", not "everything still stored".
    if plan.all_delivered() {
        Ok(())
    } else {
        Err(TransferError::Incomplete)
    }
}

/// The swarm engine behind [`download_blob_swarm`] and [`download_blob_stream`].
///
/// The manifest is fetched by trying the providers in turn, taking the first that
/// serves it (a slow or dead first provider delays this — racing them is future
/// work). Each live provider is then asked which chunks it holds, so a **partial
/// seeder** — one holding only some of the blob — can still contribute; several
/// together assemble a blob none of them has in full. Chunks are ordered by
/// `selection` and handed only to a provider that holds them; an assigned-but-
/// undelivered chunk is re-assigned, and a provider that stops responding is
/// retired.
///
/// Fetching is **work-stealing**, not round-based: each provider pulls a small
/// batch and, the moment it finishes, is re-dispatched onto whatever's still
/// pending, so a slow provider only delays its own current batch (no round
/// barrier). As chunks arrive, `emit(index, bytes)` is called in contiguous
/// playback order — index `k` only once `0..=k` are all stored — exactly once per
/// playback index (`0..N`; a chunk shared by several indices, from dedup, is
/// delivered at each of them, since a player needs every position). It's the seam
/// through which both a bulk collector and a streaming consumer receive the data.
/// Returns the (possibly incomplete) [`Plan`]; the caller checks
/// [`Plan::is_complete`].
async fn run_swarm(
    channels: Vec<Channel>,
    id: Hash,
    cfg: &Config,
    selection: Selection,
    mut emit: impl FnMut(usize, &[u8]),
) -> Result<Plan, TransferError> {
    let providers: Vec<Provider> = channels
        .into_iter()
        .map(|channel| Provider {
            channel,
            cursor: Cursor::default(),
            holds: Holdings::Known(HashSet::new()),
        })
        .collect();

    // The manifest comes from the first provider that can serve it. A provider
    // that doesn't respond (a timeout or I/O error) is retired here rather than
    // carried into the fetch rounds only to time out all over again.
    let mut manifest = None;
    let mut live = Vec::with_capacity(providers.len());
    let mut rest = providers.into_iter();
    for mut provider in rest.by_ref() {
        match fetch_manifest(&mut provider.channel, id, cfg, &mut provider.cursor).await {
            Ok(m) => {
                manifest = Some(m);
                live.push(provider);
                break;
            }
            // A non-response retires the provider; a provider that answered but
            // couldn't serve the manifest is kept (it may still have chunks).
            Err(TransferError::Timeout) | Err(TransferError::Io(_)) => {}
            Err(_) => live.push(provider),
        }
    }
    live.extend(rest); // providers we never had to try
    let manifest = manifest.ok_or(TransferError::Incomplete)?;

    // Learn each live provider's holdings, so chunks are assigned rarest-first to
    // providers that have them. A provider whose channel fails here is retired;
    // one that can't report holdings (`Absent`) is kept and probed optimistically
    // (see `fetch_haveset`).
    let mut providers = Vec::with_capacity(live.len());
    for mut provider in live {
        match fetch_haveset(
            &mut provider.channel,
            id,
            &manifest,
            cfg,
            &mut provider.cursor,
        )
        .await
        {
            Ok(holds) => {
                provider.holds = holds;
                providers.push(provider);
            }
            // A dead channel (timeout / I/O) retires the provider.
            Err(TransferError::Timeout) | Err(TransferError::Io(_)) => {}
            // Any other failure to learn holdings (a protocol/decoding error):
            // keep the provider, but as Unknown so it's still probed as a last
            // resort rather than left with an empty haveset it'd never be assigned.
            Err(_) => {
                provider.holds = Holdings::unknown();
                providers.push(provider);
            }
        }
    }
    let mut plan = Plan::new(manifest);
    plan.set_selection(selection);
    // Streaming frees each chunk once delivered (bounded memory); a bulk download
    // retains all of them to reassemble at the end.
    let drop_delivered = matches!(selection, Selection::Streaming { .. });

    // Work-stealing: instead of assigning a whole round and waiting for every
    // provider at a barrier (where one slow provider stalls the fast ones), each
    // provider pulls a small batch, and the moment it finishes we re-dispatch *it*
    // onto whatever's still pending while the others keep running. `idle` holds
    // providers waiting for work; `in_flight` the fetch tasks currently running.
    let mut idle = providers;
    let mut in_flight: JoinSet<(Provider, ChunkOutcome)> = JoinSet::new();
    // Each in-flight task's assignment, keyed by its task id. `assign` removed
    // these chunks from `pending`, so this is the only handle on them — it lets us
    // requeue a task's chunks even if the task dies with a `JoinError` (panic /
    // cancellation), rather than silently losing them.
    let mut in_flight_chunks: HashMap<tokio::task::Id, Vec<Hash>> = HashMap::new();
    dispatch(
        &mut plan,
        &mut idle,
        &mut in_flight,
        &mut in_flight_chunks,
        cfg,
    );
    while let Some(joined) = in_flight.join_next_with_id().await {
        match joined {
            Ok((id, (mut provider, outcome))) => {
                // dispatch records every task's chunks before it can be joined, so
                // a completed task's assignment is always present; a miss would be
                // a bug that silently loses work, so fail loudly instead.
                let assignment = in_flight_chunks
                    .remove(&id)
                    .expect("a completed task's assignment is tracked");
                let fetched: HashSet<Hash> = outcome.fetched.iter().map(|(h, _)| *h).collect();
                for (hash, data) in outcome.fetched {
                    plan.store(hash, data);
                }
                // Deliver any chunks now contiguously available from the front, in
                // playback order (the chunk at index k only once every earlier one
                // is stored), freeing each afterward when streaming.
                loop {
                    let index = plan.frontier();
                    match plan.chunk_at(index) {
                        // The borrow of `plan` ends with this statement, so
                        // `advance_delivery` can take `&mut plan` right after.
                        Some(bytes) => emit(index, bytes),
                        None => break,
                    }
                    plan.advance_delivery(drop_delivered);
                }
                // Chunks this provider was assigned but didn't deliver (an `Absent`,
                // an unexpected reply, or a hash mismatch). If it's still alive,
                // record the refusal so it isn't re-offered them — the guard
                // against a work-stealing livelock — then requeue for others. A
                // dead provider is dropped; its chunks just return to the pool.
                let undelivered: Vec<Hash> = assignment
                    .into_iter()
                    .filter(|h| !fetched.contains(h))
                    .collect();
                if outcome.alive {
                    for hash in &undelivered {
                        provider.holds.refuse(hash);
                    }
                    plan.requeue(undelivered);
                    idle.push(provider);
                } else {
                    plan.requeue(undelivered);
                }
            }
            // The task panicked or was cancelled: its provider is lost, but its
            // chunks must go back to the pool or the download could stall forever.
            Err(join_err) => {
                if let Some(chunks) = in_flight_chunks.remove(&join_err.id()) {
                    plan.requeue(chunks);
                }
            }
        }
        // Done when every index has been delivered — not when every chunk is
        // *stored*, since streaming drops chunks as it delivers them.
        if plan.all_delivered() {
            break;
        }
        dispatch(
            &mut plan,
            &mut idle,
            &mut in_flight,
            &mut in_flight_chunks,
            cfg,
        );
    }

    Ok(plan)
}

/// Hand each idle provider a small batch of chunks it can serve (rarest-first, via
/// [`Plan::assign`]) and spawn a fetch task for it in `in_flight`, recording the
/// batch in `tracker` (by task id) so it can be recovered if the task dies.
/// Providers with nothing to do stay in `idle` — they may get work once other
/// fetches requeue chunks. Batches are capped at [`STEAL_BATCH`] so most of the
/// work stays in the pool for whichever provider frees up next.
fn dispatch(
    plan: &mut Plan,
    idle: &mut Vec<Provider>,
    in_flight: &mut JoinSet<(Provider, ChunkOutcome)>,
    tracker: &mut HashMap<tokio::task::Id, Vec<Hash>>,
    cfg: &Config,
) {
    if idle.is_empty() || plan.pending() == 0 {
        return;
    }
    let assignment = {
        let holdings: Vec<&Holdings> = idle.iter().map(|p| &p.holds).collect();
        plan.assign(&holdings, STEAL_BATCH)
    };
    let mut still_idle = Vec::new();
    for (mut provider, chunks) in std::mem::take(idle).into_iter().zip(assignment) {
        if chunks.is_empty() {
            still_idle.push(provider);
            continue;
        }
        let cfg = *cfg;
        let recover = chunks.clone();
        let handle = in_flight.spawn(async move {
            let outcome =
                download_chunks(&mut provider.channel, &chunks, &cfg, &mut provider.cursor).await;
            (provider, outcome)
        });
        tracker.insert(handle.id(), recover);
    }
    *idle = still_idle;
}

/// Fetch and verify a blob's manifest from one provider, advancing its `cursor`.
async fn fetch_manifest<L: Link>(
    channel: &mut L,
    id: Hash,
    cfg: &Config,
    cursor: &mut Cursor,
) -> Result<Manifest, TransferError> {
    let mut wire = Wire::new(channel, cfg.initial_rtt, cfg.request_timeout, *cursor);
    let result = match exchange(&mut wire, &Message::GetManifest { id }, cfg).await {
        Ok(Message::Manifest(manifest)) if manifest.id() == id => Ok(manifest),
        Ok(Message::Manifest(_)) => Err(TransferError::Sync(SyncError::BadManifest)),
        Ok(_) => Err(TransferError::Sync(SyncError::Absent)),
        Err(e) => Err(e),
    };
    *cursor = wire.cursor();
    result
}

/// Ask one provider which of the blob's chunks it holds, decoded from the `Have`
/// bitfield against `manifest`. Advances the `cursor`; a channel error or timeout
/// is surfaced as `Err` so the caller can retire the provider.
///
/// The holdings are a scheduling hint, not a trust boundary: every chunk is still
/// verified by hash on receipt, so an inaccurate answer can never corrupt the
/// blob — it can only affect liveness (a chunk a provider has but doesn't report
/// won't be requested from it). So a provider that *can't* report its holdings —
/// `Absent` (e.g. it serves chunks by hash but doesn't store the manifest), or a
/// bitfield too short to cover the manifest — becomes [`Holdings::Unknown`]: a
/// last-resort source the scheduler probes only when no known holder can serve a
/// chunk, rather than excluding it (risking a false "unavailable") or reading a
/// truncated bitfield as "lacks the missing chunks". A genuinely unexpected reply
/// is treated as holding nothing.
async fn fetch_haveset<L: Link>(
    channel: &mut L,
    id: Hash,
    manifest: &Manifest,
    cfg: &Config,
    cursor: &mut Cursor,
) -> Result<Holdings, TransferError> {
    let mut wire = Wire::new(channel, cfg.initial_rtt, cfg.request_timeout, *cursor);
    let result = match exchange(&mut wire, &Message::GetHave { id }, cfg).await {
        // A bitfield shorter than the manifest needs is malformed/truncated;
        // reading it would falsely mark the uncovered chunks absent, so probe the
        // provider as a last resort instead. Extra trailing bytes are harmless.
        Ok(Message::Have { bits }) if bits.len() < manifest.chunks.len().div_ceil(8) => {
            Ok(Holdings::unknown())
        }
        Ok(Message::Have { bits }) => {
            let mut holds = HashSet::new();
            for (i, hash) in manifest.chunks.iter().enumerate() {
                if bits[i / 8] & (1 << (i % 8)) != 0 {
                    holds.insert(*hash);
                }
            }
            Ok(Holdings::Known(holds))
        }
        // Responsive but can't enumerate its holdings → probe as a last resort.
        Ok(Message::Absent) => Ok(Holdings::unknown()),
        // A genuinely unexpected reply: don't rely on it.
        Ok(_) => Ok(Holdings::Known(HashSet::new())),
        Err(e) => Err(e),
    };
    *cursor = wire.cursor();
    result
}

/// Fetch the listed chunks from one provider over a single session, verifying
/// each by its hash. A chunk the provider lacks or sends wrong is skipped — left
/// for another provider — and a provider that stops responding (a channel error
/// or a timeout) is retired (`alive = false`). Advances the `cursor` so the next
/// round on this channel keeps ids monotonic and preserves the straggler
/// watermark.
async fn download_chunks<L: Link>(
    channel: &mut L,
    wanted: &[Hash],
    cfg: &Config,
    cursor: &mut Cursor,
) -> ChunkOutcome {
    let mut wire = Wire::new(channel, cfg.initial_rtt, cfg.request_timeout, *cursor);
    let mut fetched = Vec::new();
    let mut alive = true;
    for &hash in wanted {
        match exchange(&mut wire, &Message::GetChunk { hash }, cfg).await {
            Ok(Message::Chunk { data }) if crypto::hash(&data) == hash => {
                fetched.push((hash, data));
            }
            // Absent, a mismatched chunk, or an unexpected message: this provider
            // didn't give us this chunk (perhaps a straggler) — try another.
            Ok(_) => {}
            // The channel timed out or broke: stop and retire this provider.
            Err(_) => {
                alive = false;
                break;
            }
        }
    }
    *cursor = wire.cursor();
    ChunkOutcome { fetched, alive }
}

/// Serve feed sync requests on `channel` from a local [`feed::Log`] until the
/// client goes idle (or the channel breaks).
pub async fn serve_feed<L: Link>(
    channel: &mut L,
    log: &feed::Log,
    cfg: &Config,
) -> Result<(), TransferError> {
    serve(channel, cfg, None, |request| sync::serve_feed(request, log)).await
}

/// Like [`serve_feed`], but serve a **live subscriber**: when the client polls
/// with [`sync::Message::Tail`] and the feed hasn't grown past its cursor, hold
/// the reply until `appended` is signaled (or a keepalive elapses), so the
/// subscriber is pushed new blocks the moment they land instead of polling. The
/// caller must signal `appended` (e.g. `notify_waiters()`) whenever it appends a
/// block to `log`.
///
/// Unlike [`serve_feed`], the log is a `Mutex` locked **per reply**, never across
/// the (unbounded) session — otherwise a live subscriber would hold the lock
/// forever and block every append. Each `serve_feed` answer is a pure, non-async
/// computation, so no lock is held across an `.await`.
pub async fn serve_feed_tail<L: Link, S: feed::Source>(
    channel: &mut L,
    source: &std::sync::Mutex<S>,
    appended: &tokio::sync::Notify,
    cfg: &Config,
) -> Result<(), TransferError> {
    serve(channel, cfg, Some(appended), |request| {
        sync::serve_feed(request, &*source.lock().expect("feed source"))
    })
    .await
}

/// Serve blob sync requests on `channel` from a local [`blob::Store`]. The store
/// must hold each blob's manifest under its own content address (see
/// [`sync::serve_blob`]).
pub async fn serve_blob<L: Link>(
    channel: &mut L,
    store: &blob::Store,
    cfg: &Config,
) -> Result<(), TransferError> {
    serve(channel, cfg, None, |request| {
        sync::serve_blob(request, store)
    })
    .await
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
        let progress_from = wire.stored();
        let deadline = Instant::now() + cfg.request_timeout;
        // Wait out one interval. A stray decodable packet — a request-type message
        // or a NACK, neither of which the client serves — is ignored without
        // extending the interval, so a peer can't stave off the stall bound (or
        // our NACKs) by dribbling irrelevant traffic. Handing a request to the
        // sync client would abort it as Unexpected, so we never return one.
        let completed = loop {
            match wire.recv(deadline).await? {
                Some(Recv::Message(message)) if !message.is_request() => break Some(message),
                Some(_) => continue,
                None => break None,
            }
        };
        if let Some(message) = completed {
            return Ok(message);
        }
        // The interval elapsed without completing the response. If fragments were
        // still arriving, the transmission is simply in progress — keep waiting
        // rather than NACK indices that are likely in flight (which would make
        // the server resend them needlessly). Only a *stalled* interval means a
        // gap is actually lost.
        if wire.stored() > progress_from {
            stalls = 0;
            continue;
        }
        // No progress: repair the gaps (NACK), or re-ask if nothing arrived yet.
        match wire.missing() {
            Some(missing) => wire.nack(missing.id, &missing.indices).await?,
            None => wire.send(request).await?,
        }
        stalls += 1;
        if stalls > cfg.retries {
            return Err(TransferError::Timeout);
        }
    }
}

/// The server loop shared by [`serve_feed`]/[`serve_blob`]: read a request,
/// answer it with `respond`, and honor NACKs by resending the missing fragments
/// of that reply; return when the client goes idle.
///
/// It also drives the congestion window: a reply that drew a NACK is a loss
/// signal (shrink); a reply the client never NACKed — evidenced by the client
/// moving on to the next request — is a clean delivery (grow). So the window
/// ramps up across a run of clean replies and backs off on loss.
async fn serve<L: Link>(
    channel: &L,
    cfg: &Config,
    tail: Option<&tokio::sync::Notify>,
    respond: impl Fn(&Message) -> Message,
) -> Result<(), TransferError> {
    // The pacer caps the RTT it uses at request_timeout, so no single pacing
    // pause reaches the peer's stall interval. This guards the usual shared-Config
    // deployment against a mistuned initial_rtt that's already at/over the timeout
    // (which would leave no headroom); real RTTs sit far below it.
    debug_assert!(
        cfg.initial_rtt < cfg.request_timeout,
        "initial_rtt ({:?}) must be well below request_timeout ({:?})",
        cfg.initial_rtt,
        cfg.request_timeout
    );
    let mut wire = Wire::new(
        channel,
        cfg.initial_rtt,
        cfg.request_timeout,
        Cursor::default(),
    );
    // Idle is measured from the last *valid* activity, so a peer can't hold the
    // session open by sending undecodable junk.
    let mut deadline = Instant::now() + cfg.idle;
    // The last request served, and whether its reply has drawn a NACK (so loss is
    // counted once per reply). Telling a *new* request from a *retransmit* of the
    // same one distinguishes clean delivery (the client moved on) from total loss
    // (the client received nothing and re-asks — partial loss would NACK instead).
    let mut last_request: Option<Message> = None;
    let mut lost = false;
    // When the last reply finished sending, for measuring RTT from the client's
    // next request (its implicit ack).
    let mut last_reply_at: Option<Instant> = None;
    loop {
        match wire.recv(deadline).await? {
            // Answer only genuine requests. A response-type message (peer
            // confusion, or a delayed packet) is ignored — replying `Absent` to
            // it would inject terminal traffic at the client.
            Some(Recv::Message(request)) if request.is_request() => {
                let retransmit = last_request.as_ref() == Some(&request);
                if wire.has_sent() {
                    if retransmit {
                        // Same request again → the client got none of the last
                        // reply: back off (don't mistake a re-ask for progress).
                        if !lost {
                            wire.on_loss();
                            lost = true;
                        }
                    } else if !lost {
                        // A different request → the client accepted the last reply
                        // cleanly: grow, and take a clean RTT sample (the gap since
                        // we finished that reply). A repaired reply's timing is
                        // muddied by the stall+NACK, so we skip it there.
                        wire.on_delivered();
                        if let Some(sent_at) = last_reply_at {
                            wire.rtt_sample(sent_at.elapsed());
                        }
                    }
                }
                if !retransmit {
                    lost = false;
                    last_request = Some(request.clone());
                }
                let mut response = respond(&request);
                // Live-tail: if this is a subscription poll (`Tail`) and the feed
                // hasn't grown past the subscriber's cursor, hold the reply until an
                // append is signaled — bounded by a keepalive kept under the client's
                // stall bound, so it heartbeats rather than timing out. This is server
                // push (new blocks the instant they land), not client polling.
                if let (Some(notify), Message::Tail { have }) = (tail, &request) {
                    let keepalive = cfg.request_timeout / 2;
                    while matches!(&response, Message::Head(h) if h.len <= *have) {
                        if timeout(keepalive, notify.notified()).await.is_err() {
                            break; // keepalive elapsed: send the unchanged head
                        }
                        response = respond(&request);
                    }
                }
                wire.send(&response).await?;
                last_reply_at = Some(Instant::now());
                deadline = Instant::now() + cfg.idle;
            }
            Some(Recv::Message(_)) => {} // response-type: ignore
            // The client is missing fragments of the reply we last sent: resend
            // just those. Only a NACK that actually causes a resend counts as
            // activity (holds the session open) — a stale, empty, or bogus one
            // resends nothing and mustn't let a client keep the session alive by
            // spamming NACKs. The first real NACK for a reply shrinks the window.
            Some(Recv::Nack { id, indices }) => {
                if wire.resend(id, &indices).await? {
                    if !lost {
                        wire.on_loss();
                        lost = true;
                    }
                    deadline = Instant::now() + cfg.idle;
                }
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
    /// The send-side congestion window (fragments per RTT), adapted by the server
    /// loop from NACK feedback, and the smoothed RTT to pace it over.
    cong: Congestion,
    rtt: Rtt,
}

impl<'a, L: Link> Wire<'a, L> {
    /// `max_rtt` caps the pacing RTT (the caller passes `request_timeout`) so a
    /// pacing pause can't be mistaken for a stall. `cursor` seeds the session
    /// state: a fresh session starts at `Cursor::default()`, but a swarm reuses
    /// one channel across several `Wire`s (a round per provider) and threads a
    /// `Cursor` so the outbound ids stay monotonic (or the server drops a reset
    /// id as a stale duplicate) and the inbound straggler watermark survives.
    fn new(link: &'a L, initial_rtt: Duration, max_rtt: Duration, cursor: Cursor) -> Self {
        Self {
            link,
            next_id: cursor.next_id,
            inbound: Reassembler::resume(cursor.accepted),
            buf: vec![0u8; MAX_DATAGRAM],
            last_sent: None,
            cong: Congestion::new(),
            rtt: Rtt::new(initial_rtt, max_rtt),
        }
    }

    /// Export the session state to carry into the next `Wire` on this channel.
    fn cursor(&self) -> Cursor {
        Cursor {
            next_id: self.next_id,
            accepted: self.inbound.accepted(),
        }
    }

    /// Whether any message has been sent yet (a reply is being served).
    fn has_sent(&self) -> bool {
        self.last_sent.is_some()
    }

    /// Grow the congestion window: the last reply was delivered without loss.
    fn on_delivered(&mut self) {
        self.cong.on_delivered();
    }

    /// Shrink the congestion window: the last reply drew a NACK (loss).
    fn on_loss(&mut self) {
        self.cong.on_loss();
    }

    /// Fold a round-trip sample into the RTT estimate used to pace sends.
    fn rtt_sample(&mut self, sample: Duration) {
        self.rtt.sample(sample);
    }

    /// Send `fragments` paced to spread a window (`cwnd`) across one RTT — a
    /// fragment every `srtt / cwnd`. Sub-millisecond intervals are accumulated
    /// and paid in one pause (timer granularity), so a short-RTT path bursts and
    /// a long-RTT path spaces out; a message small relative to the rate goes out
    /// with no pause at all.
    ///
    /// The pause is taken *before* each fragment after the first — never after
    /// the last — so a message doesn't end on a dead pause. That matters beyond
    /// wasted time: the server times RTT from when a reply finishes sending, and
    /// a trailing sleep would let the client's next request queue during it,
    /// collapsing the sample toward zero.
    async fn paced_send(
        &self,
        fragments: impl Iterator<Item = Vec<u8>>,
    ) -> Result<(), TransferError> {
        let per_fragment = self.rtt.get() / self.cong.window() as u32;
        let mut owed = Duration::ZERO;
        for (i, fragment) in fragments.enumerate() {
            if i > 0 {
                owed += per_fragment;
                if owed >= MIN_PACING_SLEEP {
                    sleep(owed).await;
                    owed = Duration::ZERO;
                }
            }
            self.link.send(&fragment).await?;
        }
        Ok(())
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
        self.paced_send(frame::fragment(id, &bytes, FRAGMENT))
            .await?;
        self.last_sent = Some((id, bytes));
        Ok(())
    }

    /// Resend the requested fragments of the last message sent. Returns whether
    /// it actually resent anything — a NACK for a superseded reply, or one whose
    /// indices are empty or all out of range, resends nothing and returns
    /// `false`, so the caller counts only *productive* repair as session
    /// activity (an empty/bogus NACK can't hold a session open). Only the
    /// requested, in-range fragments are rebuilt (via [`frame::fragment_at`]),
    /// never the whole message, so light loss costs proportionally little.
    async fn resend(&self, id: u64, indices: &[u64]) -> Result<bool, TransferError> {
        // Build just the requested fragments, releasing the borrow of `last_sent`
        // before awaiting the sends.
        let to_send: Vec<Vec<u8>> = {
            let Some((last_id, bytes)) = &self.last_sent else {
                return Ok(false);
            };
            if *last_id != id {
                return Ok(false);
            }
            let mut seen = HashSet::new();
            indices
                .iter()
                .copied()
                .filter(|i| seen.insert(*i)) // dedup, in case a NACK repeats an index
                .filter_map(|i| frame::fragment_at(*last_id, bytes, FRAGMENT, i))
                .collect()
        };
        let resent = !to_send.is_empty();
        self.paced_send(to_send.into_iter()).await?;
        Ok(resent)
    }

    /// NACK (a bounded batch of) the missing fragments of message `id`. Capped at
    /// [`frame::NACK_MAX_INDICES`] so the NACK fits one datagram; the caller
    /// re-NACKs for any remainder on the next interval.
    async fn nack(&self, id: u64, indices: &[u64]) -> Result<(), TransferError> {
        let batch = &indices[..indices.len().min(frame::NACK_MAX_INDICES)];
        self.link.send(&frame::nack_datagram(id, batch)).await?;
        Ok(())
    }

    /// Total fragments stored so far (monotonic) — lets the driver tell whether
    /// an interval made repair progress, even across a message-id switch.
    fn stored(&self) -> usize {
        self.inbound.stored()
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
                            self.inbound.push_data(id, index, count, payload)
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
            initial_rtt: Duration::from_millis(5),
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
        let (served, downloaded) = tokio::join!(
            serve_feed(&mut server, &log, &cfg),
            download_feed(&mut client, public_key, &cfg),
        );
        served.expect("server ends cleanly on idle");
        assert_eq!(downloaded.expect("download verifies"), expected);
    }

    #[tokio::test]
    async fn subscribe_receives_live_appends() {
        use std::sync::{Arc, Mutex as StdMutex};
        use tokio::sync::Notify;

        let kp = Keypair::from_seed(&[9u8; 32]);
        let public_key = kp.public();
        let log = Arc::new(StdMutex::new(Log::new(kp)));
        // Two blocks exist before anyone subscribes.
        {
            let mut l = log.lock().unwrap();
            l.append(vec![0u8; 100]);
            l.append(vec![1u8; 100]);
        }
        let appended = Arc::new(Notify::new());
        let (mut client, mut server) = lossy_pair(&[], &[]);
        let cfg = fast_cfg();

        // Server tails forever; client subscribes from 0 and forwards each block.
        let srv_log = log.clone();
        let srv_appended = appended.clone();
        let server_task = tokio::spawn(async move {
            let _ = serve_feed_tail(&mut server, &srv_log, &srv_appended, &cfg).await;
        });
        let (tx, mut rx) = mpsc::unbounded_channel();
        let client_task = tokio::spawn(async move {
            let _ = subscribe_feed(&mut client, public_key, 0, &cfg, move |index, block| {
                let _ = tx.send((index, block));
            })
            .await;
        });

        // The two existing blocks arrive.
        assert_eq!(rx.recv().await.unwrap(), (0, vec![0u8; 100]));
        assert_eq!(rx.recv().await.unwrap(), (1, vec![1u8; 100]));

        // A block appended *after* subscribing is pushed to the subscriber — no
        // reconnect, no re-fetch of the earlier blocks.
        {
            log.lock().unwrap().append(vec![2u8; 100]);
        }
        appended.notify_waiters();
        assert_eq!(rx.recv().await.unwrap(), (2, vec![2u8; 100]));

        // And another, to confirm the tail keeps flowing.
        {
            log.lock().unwrap().append(vec![3u8; 100]);
        }
        appended.notify_waiters();
        assert_eq!(rx.recv().await.unwrap(), (3, vec![3u8; 100]));

        server_task.abort();
        client_task.abort();
    }

    #[tokio::test]
    async fn subscribe_tails_a_growing_replica() {
        use std::sync::{Arc, Mutex as StdMutex};
        use tokio::sync::Notify;

        let kp = Keypair::from_seed(&[0x2Au8; 32]);
        let pk = kp.public();
        // An author log, used here only to mint signed heads + blocks; the *mirror*
        // holds a Replica of it and serves that — the author isn't in this exchange.
        let mut author = Log::new(kp);
        author.append(vec![0u8; 80]);
        author.append(vec![1u8; 80]);
        let seed: Vec<Vec<u8>> = (0..author.len())
            .map(|i| author.get(i).unwrap().to_vec())
            .collect();
        let replica = Arc::new(StdMutex::new(
            feed::Replica::new(pk, author.head(), seed).expect("faithful replica"),
        ));
        let appended = Arc::new(Notify::new());
        let (mut client, mut server) = lossy_pair(&[], &[]);
        let cfg = fast_cfg();

        let srv_replica = replica.clone();
        let srv_appended = appended.clone();
        let server_task = tokio::spawn(async move {
            let _ = serve_feed_tail(&mut server, &srv_replica, &srv_appended, &cfg).await;
        });
        let (tx, mut rx) = mpsc::unbounded_channel();
        let client_task = tokio::spawn(async move {
            let _ = subscribe_feed(&mut client, pk, 0, &cfg, move |index, block| {
                let _ = tx.send((index, block));
            })
            .await;
        });

        // The mirror serves the two blocks it already holds.
        assert_eq!(rx.recv().await.unwrap(), (0, vec![0u8; 80]));
        assert_eq!(rx.recv().await.unwrap(), (1, vec![1u8; 80]));

        // The author appends; the mirror advances its replica + signals — the
        // subscriber is pushed the new block straight from the mirror, verified.
        author.append(vec![2u8; 80]);
        let new = vec![author.get(2).unwrap().to_vec()];
        assert!(replica.lock().unwrap().advance(author.head(), new));
        appended.notify_waiters();
        assert_eq!(rx.recv().await.unwrap(), (2, vec![2u8; 80]));

        server_task.abort();
        client_task.abort();
    }
}
