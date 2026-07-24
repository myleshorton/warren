//! Real-UDP driver for the sans-IO [`swarm::Dht`].
//!
//! The DHT core does no I/O; this crate wires it to a real
//! [`tokio::net::UdpSocket`] and a real clock. The core runs in a dedicated task
//! (an actor): the public [`Node`] handle sends commands over a channel and
//! awaits a oneshot fired when the matching DHT event surfaces. That keeps the
//! `Dht` single-owner (no locks) behind an ergonomic `async` API.
//!
//! The very same core verified across the deterministic simulator now runs
//! unchanged over the network — the payoff of the sans-IO design.
//!
//! ```no_run
//! use driver::Node;
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let addr = "127.0.0.1:0".parse().unwrap();
//! // The node is bound to an Ed25519 identity; its DHT id is hash(public key).
//! let node = Node::bind(addr, crypto::Keypair::generate()).await?;
//! node.bootstrap().await?;
//! # Ok(()) }
//! ```

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use swarm::dht::{Dht, Event};
use swarm::{Contact, Message, NodeId, Packet, QueryId, Strategy};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;

mod lan;

pub use lan::LanBeacon;
pub use puncher::Config as PunchConfig;
pub use swarm::dht::ConnectOutcome;
pub use swarm::Firewall;

/// Tuning for the one-sided-random *birthday* hole punch used on symmetric-NAT
/// connects (the `Punched` outcome). Defaults match the analytic model verified
/// in `swarm::punch`; tests shrink the range to stay fast and reliable on
/// loopback (the full 64k range would bind hundreds of sockets against the whole
/// port space).
#[derive(Debug, Clone, Copy)]
pub struct BirthdayParams {
    /// Half-open port range `[start, end)` to spray / open sockets within.
    pub range: (u16, u16),
    /// Sockets the Random side opens at once (each mints one external port).
    pub sockets: usize,
    /// Random-port guesses the Consistent side sprays.
    pub probes: usize,
}

impl Default for BirthdayParams {
    fn default() -> Self {
        Self {
            // Half-open [min, max); drops only the single top port vs the
            // model's inclusive [PORT_MIN, PORT_MAX], negligible for the math.
            range: (swarm::punch::PORT_MIN, swarm::punch::PORT_MAX),
            sockets: swarm::punch::BIRTHDAY_SOCKETS,
            probes: swarm::punch::SPRAY_PROBES,
        }
    }
}

/// How a connect establishes reachability: whether it tries to open a direct
/// external port during discovery, plus the timing/parameters of the punch it
/// performs once the DHT has brokered reachability.
#[derive(Debug, Clone, Copy, Default)]
pub struct PunchTuning {
    /// Timing knobs (deadline, probe interval) for every punch primitive.
    pub config: PunchConfig,
    /// Birthday-punch parameters for the symmetric-NAT (`Punched`) path.
    pub birthday: BirthdayParams,
    /// Attempt a port mapping (PCP first, UPnP-IGD fallback) while discovering the
    /// data socket's address, advertising the explicit forward as a candidate when
    /// the gateway supports it. Off by default: it fires an SSDP multicast per
    /// connect and waits out the discovery window on networks with no gateway.
    pub port_mapping: bool,
}

/// A live, bidirectional data channel to a peer, established by a hole punch —
/// a socket already reaching the peer, over which application bytes flow.
///
/// Where [`Node::connect`] reports *whether* a peer is reachable (a
/// [`ConnectOutcome`]), a `Channel` is the *usable* path you then establish with
/// [`open_channel`] / [`DataListener`]. Built on the [`puncher`] primitives.
#[derive(Debug)]
pub struct Channel {
    socket: UdpSocket,
    peer: SocketAddr,
}

impl Channel {
    /// The peer on the far end of the channel.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Send application bytes to the peer.
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.socket.send(data).await
    }

    /// Receive application bytes from the peer. The socket is connected to the
    /// peer (see [`open_channel`] / [`DataListener::accept`]), so the OS drops
    /// datagrams from any other source before they reach us — no user-space
    /// filtering, and stray traffic can't be read as channel data.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf).await
    }
}

/// Open a data channel to a reachable peer at `peer`, punching from a fresh
/// socket bound at `bind`. `Ok(None)` means the punch didn't complete in time.
pub async fn open_channel(
    bind: SocketAddr,
    peer: SocketAddr,
    cfg: &PunchConfig,
) -> io::Result<Option<Channel>> {
    let socket = UdpSocket::bind(bind).await?;
    connect_channel(puncher::connect_to(socket, peer, cfg).await?).await
}

/// Turn a punched [`puncher::Established`] into a [`Channel`], connecting the
/// socket to the confirmed peer so the OS filters out every other source. Shared
/// by both the dial ([`open_channel`]) and accept ([`DataListener::accept`])
/// paths so they can't drift.
async fn connect_channel(established: Option<puncher::Established>) -> io::Result<Option<Channel>> {
    match established {
        Some(e) => {
            e.socket.connect(e.peer).await?;
            Ok(Some(Channel {
                socket: e.socket,
                peer: e.peer,
            }))
        }
        None => Ok(None),
    }
}

/// A bound socket awaiting an inbound data channel (the reachable side). Expose
/// [`DataListener::local_addr`] to the peer, then [`DataListener::accept`].
#[derive(Debug)]
pub struct DataListener {
    socket: UdpSocket,
}

impl DataListener {
    /// Bind a listener at `bind`.
    pub async fn bind(bind: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(bind).await?,
        })
    }

    /// The address to advertise to a peer that will `open_channel` to us.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Accept one inbound channel from a peer at `peer_host`. `Ok(None)` means
    /// none arrived in time. Only a punch from `peer_host` is accepted, so an
    /// off-path host that learns the advertised address can't race the peer.
    pub async fn accept(self, peer_host: IpAddr, cfg: &PunchConfig) -> io::Result<Option<Channel>> {
        connect_channel(puncher::accept(self.socket, peer_host, cfg).await?).await
    }
}

/// Largest datagram we read. A `Nodes` reply (up to `K` contacts + `K` peers,
/// each 39 bytes for a v4 address or 51 for v6) fits comfortably inside this.
const RECV_BUF: usize = 4096;

/// Reflectors to try when discovering a data socket's external address.
const REFLECTORS: usize = 3;
/// How long to wait for each reflector to echo before trying the next.
const REFLECT_TIMEOUT: Duration = Duration::from_millis(500);
/// Upper bound on the run loop's idle sleep: even with no pending query/connect/probe
/// (so `Dht::poll_timeout()` is `None`), wake at least this often to run
/// `handle_timeout` — which expires stale provider-announce leases. Lease GC is
/// coarse by nature, so a minute of slack is fine, and keeping it out of
/// `poll_timeout` leaves that a pure protocol-timing signal (the sim relies on that).
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(60);

/// A driver operation failed because the node's task is no longer running.
///
/// Distinct from an operation's own result (e.g. an empty lookup or a
/// [`ConnectOutcome::TimedOut`]): this means the node itself is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "driver node has shut down")
    }
}

impl std::error::Error for Closed {}

/// Result of a driver operation; `Err(Closed)` means the node has shut down.
pub type Result<T> = std::result::Result<T, Closed>;

/// The result of [`Node::connect`]: how the DHT resolved reachability, plus the
/// live [`Channel`] if the punch to the peer's data socket succeeded.
///
/// A `Direct` or `Punched` outcome normally carries a live `channel` (dialed or
/// birthday-punched, respectively). `channel` is `None` when the target wasn't
/// found, signaling timed out, the outcome is `Relayed` (both peers symmetric —
/// no direct path is possible, and a relay data path is intentionally not built,
/// as it would load relays too heavily for a serverless model), or the punch to
/// a reachable peer didn't complete in time.
/// Where a candidate address came from — for telemetry, so we can see which
/// candidate kind actually carried a successful punch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// An explicit PCP/UPnP port mapping.
    Mapped,
    /// A reflexive/STUN-observed external mapping.
    Reflexive,
    /// The socket's local (LAN) address.
    Local,
}

/// Per-connect funnel measurements, carried on [`Connection`] and in
/// [`NodeEvent::ConnectResolved`]. Purely diagnostic; never affects behaviour.
///
/// Populated in two places: the connect-side fields (`gather_ms`,
/// `reflexive_rtt_ms`, `mapped`, `local_candidates`, `local_firewall`, `total_ms`)
/// by [`Node::connect`], which owns those; the actor-side fields (`dht_ms`,
/// `punch_ms`, `strategy`, `peer_firewall`, `peer_candidates`) by the punch task,
/// which owns those. Fields not yet known are left at their `Default`.
#[derive(Debug, Clone, Default)]
pub struct ConnectStats {
    /// Candidate-gathering time (reflexive probe + optional port mapping).
    pub gather_ms: u64,
    /// RTT of the reflexive probe, if a reflector answered.
    pub reflexive_rtt_ms: Option<u64>,
    /// Whether a PCP/UPnP-mapped candidate was advertised.
    pub mapped: bool,
    /// Our advertised candidates (post prioritize-and-cap), with their kind.
    pub local_candidates: Vec<(SocketAddr, CandidateKind)>,
    /// Our sampled/pinned firewall class at connect time, if known.
    pub local_firewall: Option<Firewall>,
    /// `Command::Connect` enqueue → `Event::Connected` (DHT discovery + signaling).
    pub dht_ms: u64,
    /// Sub-split of `dht_ms`: the Kademlia iterative-lookup phase (connect start →
    /// a coordinator found). A same-LAN connect that spends seconds here points at
    /// discovery (routing/announce-propagation), not the punch.
    pub dht_lookup_ms: u64,
    /// Sub-split of `dht_ms`: the coordinator-brokered signaling round-trip (lookup
    /// done → the peer's reply). `dht_lookup_ms + dht_broker_ms == dht_ms`.
    pub dht_broker_ms: u64,
    /// Punch-primitive duration; `None` when no punch ran (Relayed/NotFound/TimedOut).
    pub punch_ms: Option<u64>,
    /// Whole `connect()` → `Connection` wall time.
    pub total_ms: u64,
    /// The punch role planned from the two firewalls.
    pub strategy: Option<Strategy>,
    /// The peer's advertised firewall class, from the connect reply.
    pub peer_firewall: Option<Firewall>,
    /// The peer's candidate addresses we actually probed (post-cap).
    pub peer_candidates: Vec<SocketAddr>,
}

#[derive(Debug)]
pub struct Connection {
    /// How the DHT resolved the connection.
    pub outcome: ConnectOutcome,
    /// The established data channel, if one was punched.
    pub channel: Option<Channel>,
    /// Funnel timings + classification for this connect (diagnostic).
    pub stats: ConnectStats,
}

/// Out-of-band node events for embedder telemetry — everything that never returns
/// through [`Node::connect`]: accept-side punches, inbound connects, NAT
/// classification, and (emitted by higher layers via [`Node::emit_event`]) the
/// Noise handshake. Delivered on the optional sink passed to
/// [`Node::bind_with_events`], mirroring the `incoming` channel: best-effort
/// `try_send`, dropped if the embedder isn't draining. Non-exhaustive so more
/// event kinds can be added without breaking matchers.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// This node's NAT sampling finished (see [`Node::sample_nat`]).
    NatClassified {
        firewall: Option<Firewall>,
        samples: u32,
        observed_host: Option<IpAddr>,
    },
    /// A peer asked to connect to us; we're about to accept + punch.
    IncomingConnect {
        initiator: NodeId,
        strategy: Strategy,
        initiator_firewall: Firewall,
        peer_candidates: u8,
    },
    /// An accept-side punch finished.
    AcceptPunch {
        initiator: NodeId,
        strategy: Strategy,
        ok: bool,
        punch_ms: u64,
        /// The channel was punched but dropped because the incoming queue was full.
        shed: bool,
    },
    /// An initiator-side connect fully resolved (mirrors the `connect()` return, so
    /// background dials that discard the return value still surface).
    ConnectResolved {
        target: NodeId,
        outcome: ConnectOutcome,
        ok: bool,
        stats: ConnectStats,
    },
    /// A Noise handshake over a punched channel completed (emitted by the embedder).
    NoiseHandshake {
        peer: NodeId,
        initiator: bool,
        ok: bool,
        dur_ms: u64,
    },
}

/// Why a [`Node::connect`] could not even reach a [`Connection`] outcome.
///
/// Distinct from a [`Connection`] whose `outcome` is `NotFound`/`TimedOut`/
/// `Relayed` (the DHT *resolved*, but the peer wasn't reachable or punchable):
/// these mean the connect never got that far — and, unlike [`Closed`], most of
/// them don't mean the node itself is gone.
#[derive(Debug)]
pub enum ConnectError {
    /// The node's background task has shut down.
    Closed,
    /// A connect to this target is already in flight on this node; only one at a
    /// time is supported, and the in-flight one is left untouched.
    InProgress,
    /// The node is bound to an unspecified address (`0.0.0.0`/`::`), so there is
    /// no concrete data address to advertise as a punch target. Bind the node to
    /// a specific local IP.
    UnspecifiedLocalAddr,
    /// Binding the local data socket for this connect failed.
    Bind(io::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Closed => write!(f, "driver node has shut down"),
            ConnectError::InProgress => write!(f, "a connect to this target is already in flight"),
            ConnectError::UnspecifiedLocalAddr => {
                write!(
                    f,
                    "node is bound to an unspecified address; connect needs a concrete local IP"
                )
            }
            ConnectError::Bind(e) => write!(f, "binding the local data socket failed: {e}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnectError::Bind(e) => Some(e),
            _ => None,
        }
    }
}

/// What the actor sends back for a connect: the [`Connection`], or `Err(())`
/// meaning a connect to that target was already in flight (mapped to
/// [`ConnectError::InProgress`] by [`Node::connect`]).
type ConnectReply = std::result::Result<Connection, ()>;

enum Command {
    AddContact(Contact),
    Bootstrap(oneshot::Sender<()>),
    Announce(NodeId, oneshot::Sender<()>),
    Lookup(NodeId, oneshot::Sender<Vec<Contact>>),
    Connect(
        NodeId,
        UdpSocket,
        Vec<SocketAddr>,
        ConnectStats,
        oneshot::Sender<ConnectReply>,
    ),
    SetFirewall(Firewall),
    PinFirewall(Firewall),
    SampleNat(usize, oneshot::Sender<NatReport>),
    NatReport(oneshot::Sender<NatReport>),
    Reflectors(oneshot::Sender<Vec<SocketAddr>>),
}

/// The result of a NAT self-classification round (see [`Node::sample_nat`]).
#[derive(Debug, Clone, Copy)]
pub struct NatReport {
    /// The classification, or `None` if fewer than `MIN_SAMPLES` observations.
    pub firewall: Option<Firewall>,
    /// How many observations backed it.
    pub samples: u32,
    /// The majority-observed external host, if any.
    pub observed_host: Option<IpAddr>,
}

/// A handle to a running DHT node backed by a real UDP socket.
///
/// Cloneable: all clones drive the same underlying node. When the last handle is
/// dropped, the node's task shuts down.
#[derive(Clone)]
pub struct Node {
    id: NodeId,
    /// The node's long-term Ed25519 identity. The DHT [`id`](Self::id) is
    /// `hash(identity.public())`, and the identity is what a punched channel's
    /// Noise handshake binds to (see `transfer::NoiseLink`).
    identity: crypto::Keypair,
    local_addr: SocketAddr,
    cmd_tx: mpsc::Sender<Command>,
    /// Whether [`Node::connect`] attempts a port mapping during discovery
    /// (from [`PunchTuning::port_mapping`]).
    port_mapping: bool,
    /// Channels punched in response to inbound connects, delivered by the actor.
    /// Shared behind a mutex so cloned handles share the single stream (accept is
    /// naturally one consumer); [`Node::next_incoming`] drains it.
    incoming: Arc<Mutex<mpsc::Receiver<Channel>>>,
    /// Diagnostic: count of datagrams received on the DHT socket. Lets a caller tell
    /// "the node sends but never receives" (a one-way network path) apart from a
    /// subtler discovery fault.
    rx: Arc<std::sync::atomic::AtomicU64>,
    /// Optional embedder telemetry sink for out-of-band [`NodeEvent`]s (accept-side
    /// punches, inbound connects, NAT classification, Noise handshakes). `None`
    /// unless the node was built with [`Node::bind_with_events`].
    events: Option<mpsc::Sender<NodeEvent>>,
}

/// A running periodic re-announce started by [`Node::keep_announced`]. Hold it
/// for as long as the content should stay discoverable; dropping it stops the
/// loop. Announce records expire unless refreshed, so a long-lived provider
/// re-announces both to renew its lease, to survive DHT churn — the closest-K set
/// near a topic changes as peers come and go — and to follow a topic that rotates
/// by epoch.
#[must_use = "dropping the Announcer immediately stops the re-announce loop; bind it to a variable that lives as long as you want to stay discoverable"]
pub struct Announcer {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Announcer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Node {
    /// Bind a UDP socket at `bind_addr` and start the node under the Ed25519
    /// `identity`, using default punch tuning. The DHT id is `hash(public key)`.
    pub async fn bind(bind_addr: SocketAddr, identity: crypto::Keypair) -> io::Result<Node> {
        Node::bind_with(bind_addr, identity, PunchTuning::default()).await
    }

    /// Like [`Node::bind`], but with explicit punch tuning — chiefly to shrink
    /// the birthday port range for fast, reliable loopback tests.
    ///
    /// The node's DHT id is derived from `identity`: `NodeId = hash(public key)`,
    /// so the id can never be claimed without the matching secret, and a punched
    /// channel's Noise handshake can prove the peer holds it.
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the birthday port range is
    /// invalid (`start` must satisfy `1 <= start < end`) — validated here so a
    /// bad range fails at construction rather than panicking the node's task
    /// when a `Punched` connect later invokes the spray/open primitives.
    pub async fn bind_with(
        bind_addr: SocketAddr,
        identity: crypto::Keypair,
        tuning: PunchTuning,
    ) -> io::Result<Node> {
        Node::bind_inner(bind_addr, identity, tuning, None).await
    }

    /// Like [`Node::bind_with`], but also attaches a telemetry sink that receives
    /// out-of-band [`NodeEvent`]s (accept-side punches, inbound connects, NAT
    /// classification, and Noise handshakes emitted by higher layers). Best-effort:
    /// events are `try_send` and dropped if the receiver isn't drained, so telemetry
    /// can never back-pressure the node.
    pub async fn bind_with_events(
        bind_addr: SocketAddr,
        identity: crypto::Keypair,
        tuning: PunchTuning,
        events: mpsc::Sender<NodeEvent>,
    ) -> io::Result<Node> {
        Node::bind_inner(bind_addr, identity, tuning, Some(events)).await
    }

    async fn bind_inner(
        bind_addr: SocketAddr,
        identity: crypto::Keypair,
        tuning: PunchTuning,
        events: Option<mpsc::Sender<NodeEvent>>,
    ) -> io::Result<Node> {
        let (lo, hi) = tuning.birthday.range;
        if !(lo >= 1 && lo < hi) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid birthday port range {:?}: need 1 <= start < end",
                    (lo, hi)
                ),
            ));
        }
        let id = NodeId::from_bytes(crypto::hash(identity.public().as_bytes()));
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        let rx = Arc::new(std::sync::atomic::AtomicU64::new(0));
        tokio::spawn(run(
            Dht::new(id),
            socket,
            cmd_rx,
            incoming_tx,
            tuning,
            rx.clone(),
            events.clone(),
        ));
        Ok(Node {
            id,
            identity,
            local_addr,
            cmd_tx,
            port_mapping: tuning.port_mapping,
            incoming: Arc::new(Mutex::new(incoming_rx)),
            rx,
            events,
        })
    }

    /// Emit an out-of-band [`NodeEvent`] to the embedder's telemetry sink, if one
    /// was attached ([`Node::bind_with_events`]). Best-effort and non-blocking —
    /// used by higher layers (e.g. `warren::protocol` for Noise-handshake timing).
    pub fn emit_event(&self, ev: NodeEvent) {
        if let Some(tx) = &self.events {
            let _ = tx.try_send(ev);
        }
    }

    /// Diagnostic: total datagrams received on the DHT socket since bind. A node that
    /// is clearly sending (announces land on peers) but whose count stays at 0 has a
    /// one-way inbound path — the network/OS is dropping return traffic.
    pub fn inbound_datagrams(&self) -> u64 {
        self.rx.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// This node's id.
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// This node's long-term Ed25519 identity. The DHT id is `hash(public key)`;
    /// a punched channel's Noise handshake (`transfer::NoiseLink`) signs its
    /// per-connection static with this key so the peer can prove who it reached.
    pub fn identity(&self) -> &crypto::Keypair {
        &self.identity
    }

    /// The socket address this node is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// A [`Contact`] pointing at this node (for seeding others as a bootstrap).
    pub fn contact(&self) -> Contact {
        Contact::new(self.id, self.local_addr)
    }

    /// Seed a bootstrap contact into the routing table.
    pub async fn add_contact(&self, contact: Contact) -> Result<()> {
        self.cmd_tx
            .send(Command::AddContact(contact))
            .await
            .map_err(|_| Closed)
    }

    /// Declare this node's firewall type, used when planning a connect's punch
    /// strategy. Normally derived from NAT self-classification; set explicitly to
    /// exercise the symmetric-NAT (`Punched`) path. Defaults to `Open`.
    pub async fn set_firewall(&self, firewall: Firewall) -> Result<()> {
        self.cmd_tx
            .send(Command::SetFirewall(firewall))
            .await
            .map_err(|_| Closed)
    }

    /// Pin the firewall class advertised in connect signaling, overriding sampled
    /// classification. Use for a node the embedder knows is publicly reachable (a
    /// VPS): runtime sampling can't prove Open vs Consistent, so pinning `Open`
    /// keeps its fast Direct path. Phones should not pin — let them advertise what
    /// [`Node::sample_nat`] finds.
    pub async fn pin_firewall(&self, firewall: Firewall) -> Result<()> {
        self.cmd_tx
            .send(Command::PinFirewall(firewall))
            .await
            .map_err(|_| Closed)
    }

    /// Sample this node's NAT class: probe up to `count` known peers and wait for
    /// the round to resolve, returning the classification (`None` until enough
    /// samples), the sample count, and the majority-observed external host. Feeds
    /// the class advertised in subsequent connect signaling. An empty routing table
    /// resolves immediately with zero samples.
    pub async fn sample_nat(&self, count: usize) -> Result<NatReport> {
        self.request(|tx| Command::SampleNat(count, tx)).await
    }

    /// The current NAT classification without starting a new sample round.
    pub async fn nat_report(&self) -> Result<NatReport> {
        self.request(Command::NatReport).await
    }

    /// Bootstrap (self-lookup) and wait for it to settle.
    pub async fn bootstrap(&self) -> Result<()> {
        self.request(Command::Bootstrap).await
    }

    /// Announce this node under `topic` and wait for the announce to complete.
    pub async fn announce(&self, topic: NodeId) -> Result<()> {
        self.request(|tx| Command::Announce(topic, tx)).await
    }

    /// Look up peers announced under `topic`.
    pub async fn lookup(&self, topic: NodeId) -> Result<Vec<Contact>> {
        self.request(|tx| Command::Lookup(topic, tx)).await
    }

    /// Keep re-announcing under a set of topics until the returned [`Announcer`]
    /// is dropped. `topics` is called once now and then once per `interval`; each
    /// call returns the topics to announce *at that moment*, so a caller can
    /// rotate them over time (e.g. return the current and next epoch's blinded
    /// topic — see the `stream` example). The clock and any rotation live in the
    /// caller's closure; this method only schedules the repetition.
    ///
    /// The first announce round is awaited before this returns (so a healthy node
    /// is discoverable immediately), but it is best-effort: its errors are ignored,
    /// so if the node is already shutting down the returned `Announcer` may wrap a
    /// loop that never successfully announces. Later rounds run in the background;
    /// there an announce error means the node has shut down (`announce` only fails
    /// with [`Closed`]), so the loop exits rather than spin. A zero `interval` is a
    /// misuse and is floored to a nonzero value (otherwise the timer would panic).
    pub async fn keep_announced<F>(&self, interval: Duration, topics: F) -> Announcer
    where
        F: Fn() -> Vec<NodeId> + Send + 'static,
    {
        // `interval_at` panics on a zero period; flooring at 1ms prevents that
        // without disturbing any sensible cadence (a real re-announce interval is
        // orders of magnitude larger).
        let interval = interval.max(Duration::from_millis(1));
        for topic in topics() {
            let _ = self.announce(topic).await;
        }
        let node = self.clone();
        let task = tokio::spawn(async move {
            // Start one interval out: the initial round above already ran. Use a
            // checked add so an absurdly large interval can't panic the task on
            // overflow; falling back to "now" just fires the first tick sooner.
            let start = tokio::time::Instant::now()
                .checked_add(interval)
                .unwrap_or_else(tokio::time::Instant::now);
            let mut ticker = tokio::time::interval_at(start, interval);
            // After a scheduling stall, keep pacing at the interval rather than
            // firing a catch-up burst of announces (the default `Burst`).
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                for topic in topics() {
                    if node.announce(topic).await.is_err() {
                        return; // node shut down; nothing left to announce
                    }
                }
            }
        });
        Announcer { task }
    }

    /// Connect to `target` by id, coordinated over the DHT: discover it, broker
    /// signaling through a coordinator, and punch a data channel — all from one
    /// call. The returned [`Connection`] carries the reachability outcome and the
    /// live [`Channel`] when the punch succeeds.
    ///
    /// The data socket is bound here (not in the actor) so a local bind failure
    /// surfaces as [`ConnectError::Bind`] rather than being conflated with the
    /// node shutting down. Its externally-observed address is discovered via a
    /// reflexive probe (so a NATed peer learns a punchable address) before being
    /// advertised through the DHT signaling.
    pub async fn connect(&self, target: NodeId) -> std::result::Result<Connection, ConnectError> {
        // The data socket's address is advertised to the peer as the punch
        // target, so it must be concrete. A node bound to 0.0.0.0/:: has no such
        // address to offer.
        if self.local_addr.ip().is_unspecified() {
            return Err(ConnectError::UnspecifiedLocalAddr);
        }
        let data_sock = UdpSocket::bind(SocketAddr::new(self.local_addr.ip(), 0))
            .await
            .map_err(ConnectError::Bind)?;
        let local = data_sock.local_addr().map_err(ConnectError::Bind)?;
        // Gather the data socket's candidate addresses to advertise as punch
        // targets: the reflexive probe, an optional explicit UPnP mapping, and the
        // local address. Always includes `local`, so it's non-empty (correct on an
        // unNATed host).
        let t0 = Instant::now();
        let reflectors = self.reflectors().await.map_err(|_| ConnectError::Closed)?;
        let gather_start = Instant::now();
        let cands =
            gather_candidates(&data_sock, self.id, local, &reflectors, self.port_mapping).await;
        // Connect-side funnel stats, threaded through so the actor can fold in the
        // DHT/punch fields and emit a complete `ConnectResolved`.
        let stats = ConnectStats {
            gather_ms: gather_start.elapsed().as_millis() as u64,
            reflexive_rtt_ms: cands.reflexive_rtt.map(|d| d.as_millis() as u64),
            mapped: cands.mapped,
            local_candidates: cands.kinds,
            ..Default::default()
        };
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Connect(target, data_sock, cands.addrs, stats, tx))
            .await
            .map_err(|_| ConnectError::Closed)?;
        match rx.await {
            Ok(Ok(mut conn)) => {
                // Exact end-to-end wall time (supersedes the punch task's estimate).
                conn.stats.total_ms = t0.elapsed().as_millis() as u64;
                Ok(conn)
            }
            Ok(Err(())) => Err(ConnectError::InProgress),
            Err(_) => Err(ConnectError::Closed),
        }
    }

    /// Await the next channel opened by a peer that connected *to us*. The peer
    /// side of [`Node::connect`]: a node that has announced itself surfaces each
    /// inbound channel here. Waits until one is punched (or [`Closed`] if the
    /// node shuts down).
    pub async fn next_incoming(&self) -> Result<Channel> {
        self.incoming.lock().await.recv().await.ok_or(Closed)
    }

    /// A few known peers to use as reflexive-probe reflectors (closest to us).
    async fn reflectors(&self) -> Result<Vec<SocketAddr>> {
        self.request(Command::Reflectors).await
    }

    /// Send a command carrying a reply channel and await its result, mapping a
    /// closed channel (the node's task has stopped) to [`Closed`].
    async fn request<T>(&self, make: impl FnOnce(oneshot::Sender<T>) -> Command) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(make(tx)).await.map_err(|_| Closed)?;
        rx.await.map_err(|_| Closed)
    }
}

/// Best-effort emit to the optional embedder telemetry sink; dropped if absent or full.
fn emit(events: &Option<mpsc::Sender<NodeEvent>>, ev: NodeEvent) {
    if let Some(tx) = events {
        let _ = tx.try_send(ev);
    }
}

/// The node's event loop: owns the `Dht`, the socket, and the pending-op maps.
async fn run(
    mut dht: Dht,
    socket: UdpSocket,
    mut cmd_rx: mpsc::Receiver<Command>,
    incoming_tx: mpsc::Sender<Channel>,
    tuning: PunchTuning,
    rx_count: Arc<std::sync::atomic::AtomicU64>,
    events: Option<mpsc::Sender<NodeEvent>>,
) {
    let start = Instant::now();
    let now = || start.elapsed().as_millis() as u64;
    let mut buf = vec![0u8; RECV_BUF];

    // The interface to bind per-connection data sockets on: the same host as the
    // DHT socket, a fresh ephemeral port each time.
    let data_ip = socket
        .local_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    // Timing + birthday parameters for the punch once the DHT brokers reachability.
    let punch_cfg = tuning.config;
    let birthday = tuning.birthday;
    // Whether accept-side discovery also attempts a port mapping.
    let port_mapping = tuning.port_mapping;

    // Bootstrap waiters are keyed by the query id so a stray QueryFinished can't
    // resolve them and concurrent bootstraps don't clobber each other. Announce
    // and lookup keep a list of waiters per key: a second caller for an in-flight
    // key joins the existing operation rather than starting a duplicate.
    let mut pending_bootstrap: HashMap<QueryId, oneshot::Sender<()>> = HashMap::new();
    let mut pending_announce: HashMap<NodeId, Vec<oneshot::Sender<()>>> = HashMap::new();
    let mut pending_lookup: HashMap<NodeId, Vec<oneshot::Sender<Vec<Contact>>>> = HashMap::new();
    // A connect holds a pre-bound data socket (whose address is advertised to the
    // peer) until reachability resolves, then punches on it. One connect per
    // target at a time: a second is rejected with `InProgress`, leaving the
    // in-flight one untouched.
    let mut pending_connect: HashMap<
        NodeId,
        (UdpSocket, u64, ConnectStats, oneshot::Sender<ConnectReply>),
    > = HashMap::new();
    // Callers awaiting a NAT sample round; resolved together on the next
    // `Event::NatSampleFinished`.
    let mut pending_nat_sample: Vec<oneshot::Sender<NatReport>> = Vec::new();
    // Accept-side reflexive probes run off the actor (they'd block it) and feed
    // their result back here; the actor then replies with the discovered address
    // and starts the punch. The actor keeps `reflexive_tx` so the channel stays
    // open even with no probe in flight.
    let (reflexive_tx, mut reflexive_rx) = mpsc::channel::<ReflexiveDone>(64);

    loop {
        // Deliver completed operations, then flush. Order matters:
        // `accept_connect` (fired while handling `IncomingConnect` below) queues
        // a reply into the outbox, so events must be drained *before* the flush
        // or that reply would sit unsent until the next wake.
        while let Some(ev) = dht.poll_event() {
            match ev {
                Event::QueryFinished { query, .. } => {
                    if let Some(tx) = pending_bootstrap.remove(&query) {
                        let _ = tx.send(());
                    }
                }
                Event::LookupFinished { topic, peers } => {
                    for tx in pending_lookup.remove(&topic).unwrap_or_default() {
                        let _ = tx.send(peers.clone());
                    }
                }
                Event::AnnounceFinished { topic } => {
                    for tx in pending_announce.remove(&topic).unwrap_or_default() {
                        let _ = tx.send(());
                    }
                }
                Event::Connected {
                    target,
                    outcome,
                    mut peer_data_addrs,
                    strategy,
                    peer_firewall,
                    lookup_ms,
                } => {
                    if let Some((data_sock, cmd_ms, mut stats, tx)) =
                        pending_connect.remove(&target)
                    {
                        // The peer's candidate set is untrusted (from a Signal, so
                        // only buffer-bounded); prioritize and cap what we actually
                        // probe, so a peer can't make us spray hundreds of packets
                        // at addresses of its choosing (a UDP-scan / amplification
                        // vector) and its routable candidate survives the cap even
                        // if it front-loaded junk.
                        prioritize_and_cap(&mut peer_data_addrs);
                        // Fold the actor-side funnel fields into the connect-side
                        // stats the caller threaded in.
                        stats.dht_ms = now().saturating_sub(cmd_ms);
                        // Split the DHT cost into lookup vs. broker. swarm reports the
                        // lookup duration when it finds a coordinator; `None` means the
                        // connect never got past the lookup (timed out / found nobody),
                        // so attribute the whole cost to lookup.
                        stats.dht_lookup_ms = lookup_ms.unwrap_or(stats.dht_ms).min(stats.dht_ms);
                        stats.dht_broker_ms = stats.dht_ms.saturating_sub(stats.dht_lookup_ms);
                        stats.strategy = strategy;
                        stats.peer_firewall = peer_firewall;
                        stats.peer_candidates = peer_data_addrs.clone();
                        stats.local_firewall = dht.firewall();
                        // Seed the birthday RNG from the pre-bound socket's port so
                        // concurrent connects don't spray identical port sequences.
                        let seed = data_sock.local_addr().map(|a| a.port()).unwrap_or(0) as u64;
                        spawn_connect_punch(PunchJob {
                            data_sock,
                            own_host: data_ip,
                            peers: peer_data_addrs,
                            strategy,
                            outcome,
                            cfg: punch_cfg,
                            birthday,
                            seed,
                            tx,
                            target,
                            stats,
                            events: events.clone(),
                        });
                    }
                }
                Event::NatSampleFinished {
                    firewall,
                    samples,
                    observed_host,
                } => {
                    let report = NatReport {
                        firewall,
                        samples: samples as u32,
                        observed_host,
                    };
                    for tx in pending_nat_sample.drain(..) {
                        let _ = tx.send(report);
                    }
                    emit(
                        &events,
                        NodeEvent::NatClassified {
                            firewall,
                            samples: samples as u32,
                            observed_host,
                        },
                    );
                }
                Event::IncomingConnect {
                    initiator,
                    mut initiator_data_addrs,
                    strategy,
                    initiator_firewall,
                } => {
                    // Stand up a data socket and gather its candidate addresses via
                    // a reflexive probe — off the actor (it awaits a round-trip),
                    // feeding them back so we then reply with them and run the
                    // punch (see the `reflexive_rx` branch below). Decline if the
                    // node is bound to an unspecified address: the data socket's
                    // address would be unspecified too, unpunchable by the peer
                    // (mirrors the outbound `UnspecifiedLocalAddr` check); the
                    // initiator times out. Decline too if the initiator offered no
                    // candidate host — there's nowhere to punch to. The candidate
                    // list is untrusted (buffer-bounded only), so prioritize and
                    // cap it first — this bounds both the O(n^2) dedup and the
                    // spray fan-out, and keeps its routable hosts.
                    prioritize_and_cap(&mut initiator_data_addrs);
                    let peer_hosts = candidate_hosts(&initiator_data_addrs);
                    emit(
                        &events,
                        NodeEvent::IncomingConnect {
                            initiator,
                            strategy,
                            initiator_firewall,
                            peer_candidates: initiator_data_addrs.len().min(255) as u8,
                        },
                    );
                    if !data_ip.is_unspecified() && !peer_hosts.is_empty() {
                        if let Ok(data_sock) = UdpSocket::bind(SocketAddr::new(data_ip, 0)).await {
                            if let Ok(local) = data_sock.local_addr() {
                                let id = dht.id();
                                let reflectors = dht
                                    .closest(&id, REFLECTORS)
                                    .into_iter()
                                    .map(|c| c.addr)
                                    .collect();
                                spawn_reflexive_probe(ReflexiveProbe {
                                    data_sock,
                                    id,
                                    local,
                                    reflectors,
                                    initiator,
                                    peer_hosts,
                                    strategy,
                                    seed: local.port() as u64,
                                    port_mapping,
                                    done: reflexive_tx.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
        // Flush everything the core wants to send. A dropped datagram is fine:
        // this is best-effort UDP and the DHT tolerates loss via query/connect
        // timeouts, so we don't tear the node down on a transient send error.
        while let Some(t) = dht.poll_transmit() {
            let _ = socket.send_to(&t.data, t.to).await;
        }

        // Sleep until the core's next deadline, but never longer than the
        // housekeeping interval — so time-based maintenance (expiring announce
        // leases in handle_timeout) still runs on an otherwise-idle node, whose
        // poll_timeout() is None because no query/connect/probe is pending.
        let delay = match dht.poll_timeout() {
            Some(deadline) => {
                Duration::from_millis(deadline.saturating_sub(now())).min(HOUSEKEEPING_INTERVAL)
            }
            None => HOUSEKEEPING_INTERVAL,
        };

        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    None => return, // all handles dropped
                    Some(Command::AddContact(c)) => dht.add_contact(c),
                    Some(Command::Bootstrap(tx)) => {
                        let qid = dht.bootstrap(now());
                        pending_bootstrap.insert(qid, tx);
                    }
                    Some(Command::Announce(topic, tx)) => {
                        let waiters = pending_announce.entry(topic).or_default();
                        let first = waiters.is_empty();
                        waiters.push(tx);
                        if first {
                            dht.announce(topic, now());
                        }
                    }
                    Some(Command::Lookup(topic, tx)) => {
                        let waiters = pending_lookup.entry(topic).or_default();
                        let first = waiters.is_empty();
                        waiters.push(tx);
                        if first {
                            dht.lookup(topic, now());
                        }
                    }
                    Some(Command::Connect(target, data_sock, data_addrs, stats, tx)) => {
                        // The socket is already bound by `Node::connect`. Only one
                        // connect per target at a time; reject a second rather than
                        // displace the in-flight one's waiter.
                        match pending_connect.entry(target) {
                            Entry::Occupied(_) => {
                                let _ = tx.send(Err(()));
                            }
                            Entry::Vacant(slot) => {
                                slot.insert((data_sock, now(), stats, tx));
                                dht.connect(target, data_addrs, now());
                            }
                        }
                    }
                    Some(Command::SetFirewall(fw)) => dht.set_firewall(fw),
                    Some(Command::PinFirewall(fw)) => dht.pin_firewall(fw),
                    Some(Command::SampleNat(count, tx)) => {
                        dht.sample_nat(now(), count);
                        pending_nat_sample.push(tx);
                    }
                    Some(Command::NatReport(tx)) => {
                        let _ = tx.send(NatReport {
                            firewall: dht.firewall(),
                            samples: dht.nat_samples() as u32,
                            observed_host: dht.nat_observed_host(),
                        });
                    }
                    Some(Command::Reflectors(tx)) => {
                        let id = dht.id();
                        let addrs = dht.closest(&id, REFLECTORS).into_iter().map(|c| c.addr).collect();
                        let _ = tx.send(addrs);
                    }
                }
            }
            recv = socket.recv_from(&mut buf) => {
                match recv {
                    Ok((n, from)) => {
                        rx_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        dht.handle_input(from, &buf[..n], now());
                    }
                    // Transient, e.g. an ICMP error surfaced from a prior send;
                    // the datagram is lost but the socket is fine — keep going.
                    Err(e) if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                    ) => {}
                    // A genuinely broken socket: shut the node down cleanly
                    // (callers get `Closed`) rather than busy-spin on the error.
                    Err(_) => return,
                }
            }
            done = reflexive_rx.recv() => {
                if let Some(done) = done {
                    // The accept-side reflexive probe finished: reply to the
                    // initiator with our candidate addresses, then run the punch on
                    // the data socket per the planned strategy.
                    dht.accept_connect(done.initiator, done.external_addrs, now());
                    spawn_accept_punch(AcceptJob {
                        data_sock: done.data_sock,
                        own_host: data_ip,
                        peer_hosts: done.peer_hosts,
                        strategy: done.strategy,
                        cfg: punch_cfg,
                        birthday,
                        seed: done.seed,
                        incoming_tx: incoming_tx.clone(),
                        initiator: done.initiator,
                        events: events.clone(),
                    });
                }
            }
            _ = tokio::time::sleep(delay) => {
                dht.handle_timeout(now());
            }
        }
    }
}

/// The initiator side of a punch after a `connect` resolves.
struct PunchJob {
    /// The data socket pre-bound by `Node::connect` (used only for a `Direct`
    /// dial; the birthday primitives bind their own sockets).
    data_sock: UdpSocket,
    /// Our data host, to bind spray/birthday sockets on.
    own_host: IpAddr,
    /// The peer's data-socket candidate addresses (Direct dials the whole set; the
    /// birthday roles spray toward / are targeted at their distinct hosts). Empty
    /// when there is no peer to punch to.
    peers: Vec<SocketAddr>,
    /// Our punch role, as planned by the core.
    strategy: Option<Strategy>,
    /// The reachability outcome to report alongside any channel.
    outcome: ConnectOutcome,
    cfg: PunchConfig,
    birthday: BirthdayParams,
    seed: u64,
    tx: oneshot::Sender<ConnectReply>,
    /// Telemetry: the peer id, the funnel stats gathered so far (the punch task
    /// fills `punch_ms`/`total_ms`), and the embedder sink for `ConnectResolved`.
    target: NodeId,
    stats: ConnectStats,
    events: Option<mpsc::Sender<NodeEvent>>,
}

/// The reachable side of a punch after an `IncomingConnect`.
struct AcceptJob {
    data_sock: UdpSocket,
    own_host: IpAddr,
    /// The initiator's candidate data hosts — the only sources we accept a punch
    /// from / spray toward.
    peer_hosts: Vec<IpAddr>,
    strategy: Strategy,
    cfg: PunchConfig,
    birthday: BirthdayParams,
    seed: u64,
    incoming_tx: mpsc::Sender<Channel>,
    /// Telemetry: the initiating peer and the embedder sink for `AcceptPunch`.
    initiator: NodeId,
    events: Option<mpsc::Sender<NodeEvent>>,
}

/// Inputs to an accept-side reflexive probe task.
struct ReflexiveProbe {
    data_sock: UdpSocket,
    id: NodeId,
    local: SocketAddr,
    reflectors: Vec<SocketAddr>,
    initiator: NodeId,
    peer_hosts: Vec<IpAddr>,
    strategy: Strategy,
    seed: u64,
    /// Whether to also attempt a port mapping when gathering candidates.
    port_mapping: bool,
    done: mpsc::Sender<ReflexiveDone>,
}

/// Result of an accept-side reflexive probe, fed back into the actor loop.
struct ReflexiveDone {
    initiator: NodeId,
    /// Our own data-socket candidate addresses, to advertise to the initiator.
    external_addrs: Vec<SocketAddr>,
    data_sock: UdpSocket,
    peer_hosts: Vec<IpAddr>,
    strategy: Strategy,
    seed: u64,
}

/// Gather the accept-side data socket's candidate addresses off the actor, then
/// hand them (and the socket) back so the actor can reply and punch. Runs in its
/// own task because the probe awaits a reflector round-trip.
fn spawn_reflexive_probe(p: ReflexiveProbe) {
    tokio::spawn(async move {
        let external_addrs =
            gather_candidates(&p.data_sock, p.id, p.local, &p.reflectors, p.port_mapping)
                .await
                .addrs;
        let _ = p
            .done
            .send(ReflexiveDone {
                initiator: p.initiator,
                external_addrs,
                data_sock: p.data_sock,
                peer_hosts: p.peer_hosts,
                strategy: p.strategy,
                seed: p.seed,
            })
            .await;
    });
}

/// Punch a data channel to the peer that a `connect` resolved, then report the
/// [`Connection`] to the waiting caller. Runs in its own task so the punch's
/// wait doesn't block the actor loop. The strategy picks the primitive: `Direct`
/// dials the peer's data socket; the birthday roles spray / open sockets toward
/// the peer's host; `Relay`/`None` report no channel.
fn spawn_connect_punch(job: PunchJob) {
    let PunchJob {
        data_sock,
        own_host,
        peers,
        strategy,
        outcome,
        cfg,
        birthday,
        seed,
        tx,
        target,
        mut stats,
        events,
    } = job;
    tokio::spawn(async move {
        let hosts = candidate_hosts(&peers);
        let punch_start = Instant::now();
        // `ran` marks whether a punch primitive actually executed (so `punch_ms`
        // is `None` for Relay/no-strategy, distinguishing "no path" from "0 ms").
        let mut ran = true;
        let channel = match strategy {
            // No candidate to punch to (should not happen post-`on_signal` guard).
            _ if peers.is_empty() => {
                drop(data_sock);
                ran = false;
                None
            }
            Some(Strategy::Direct) => punch_direct(data_sock, &peers, &cfg).await,
            Some(Strategy::SprayRandomPorts) => {
                // The birthday primitives bind their own sockets; free the
                // pre-bound one now so its FD/port can't collide with them.
                drop(data_sock);
                punch_spray(own_host, &hosts, &cfg, birthday, seed).await
            }
            Some(Strategy::OpenBirthdaySockets) => {
                drop(data_sock);
                punch_open(own_host, &hosts, &cfg, birthday, seed).await
            }
            // Relay (symmetric↔symmetric: no direct path, and relaying is not
            // built by design) / no strategy.
            _ => {
                drop(data_sock);
                ran = false;
                None
            }
        };
        stats.punch_ms = ran.then(|| punch_start.elapsed().as_millis() as u64);
        // Event-side total (the return path overwrites this with the exact wall
        // time in `Node::connect`): the funnel phases we can see from here.
        stats.total_ms = stats.gather_ms + stats.dht_ms + stats.punch_ms.unwrap_or(0);
        emit(
            &events,
            NodeEvent::ConnectResolved {
                target,
                outcome,
                ok: channel.is_some(),
                stats: stats.clone(),
            },
        );
        let _ = tx.send(Ok(Connection {
            outcome,
            channel,
            stats,
        }));
    });
}

/// Accept a punch from the initiator per its planned strategy and, on success,
/// hand the channel to the node's incoming stream. Runs in its own task for the
/// same reason as [`spawn_connect_punch`].
fn spawn_accept_punch(job: AcceptJob) {
    let AcceptJob {
        data_sock,
        own_host,
        peer_hosts,
        strategy,
        cfg,
        birthday,
        seed,
        incoming_tx,
        initiator,
        events,
    } = job;
    tokio::spawn(async move {
        let punch_start = Instant::now();
        let channel = match strategy {
            Strategy::Direct => punch_accept(data_sock, &peer_hosts, &cfg).await,
            Strategy::SprayRandomPorts => {
                // Birthday primitives bind their own sockets (see connect side).
                drop(data_sock);
                punch_spray(own_host, &peer_hosts, &cfg, birthday, seed).await
            }
            Strategy::OpenBirthdaySockets => {
                drop(data_sock);
                punch_open(own_host, &peer_hosts, &cfg, birthday, seed).await
            }
            Strategy::Relay => {
                drop(data_sock);
                None
            }
        };
        let punch_ms = punch_start.elapsed().as_millis() as u64;
        let ok = channel.is_some();
        let mut shed = false;
        if let Some(channel) = channel {
            // Non-blocking: if the application isn't draining `next_incoming`
            // (queue full), drop this channel rather than park the task holding
            // its socket. A flood of inbound connects is shed at the queue bound
            // instead of accumulating blocked tasks; the peer can retry.
            shed = incoming_tx.try_send(channel).is_err();
        }
        emit(
            &events,
            NodeEvent::AcceptPunch {
                initiator,
                strategy,
                ok,
                punch_ms,
                shed,
            },
        );
    });
}

/// Lifetime requested for a connect's port mapping. Kept short deliberately: the
/// mapping only has to survive until the punch completes — once punched, the
/// channel rides the hole our own outbound packets keep open, so the forward is
/// no longer needed. A short lease means a forward auto-expires soon after the
/// connect instead of lingering on the gateway (we hold no handle to delete it,
/// and don't renew — both are future work), so many connects can't pile up
/// long-lived forwards.
const MAP_LIFETIME: Duration = Duration::from_secs(120);
/// Label the mapping carries in the router's UI.
const MAP_DESCRIPTION: &str = "warren";
/// Overall bound on the port-mapping attempt, so a slow or half-speaking gateway
/// can't stall a connect past this even though the reflexive probe has answered.
/// Leaves room for the combined path (a brief PCP attempt, then a UPnP fallback).
const MAP_TIMEOUT: Duration = Duration::from_secs(8);
/// Cap on advertised candidate addresses. Only three sources exist today (mapped,
/// reflexive, local); the cap bounds the set if that grows and keeps the Signal
/// small.
const MAX_CANDIDATES: usize = 4;

/// Gather this data socket's candidate addresses to advertise, most-preferred
/// first and deduplicated. Sources, in order: an explicit port mapping (PCP-first
/// with a UPnP-IGD fallback, when `port_mapping` is set, the socket is IPv4, and
/// the mapped IP is publicly routable), the reflexive/STUN-observed mapping, and
/// the local address. Always non-empty — the local address is the floor — and
/// capped at [`MAX_CANDIDATES`]. The peer tries them in order, so a wrong guess (a
/// stale reflexive mapping, a CGNAT external IP, a multi-homed host) costs nothing.
/// The advertised candidate set plus the telemetry the connect funnel records
/// about how it was gathered.
struct Candidates {
    /// The addresses to advertise, most-preferred first, capped.
    addrs: Vec<SocketAddr>,
    /// Each advertised address paired with where it came from.
    kinds: Vec<(SocketAddr, CandidateKind)>,
    /// RTT of the reflexive probe, if a reflector answered.
    reflexive_rtt: Option<Duration>,
    /// Whether a routable port mapping was obtained and advertised.
    mapped: bool,
}

async fn gather_candidates(
    sock: &UdpSocket,
    id: NodeId,
    local: SocketAddr,
    reflectors: &[SocketAddr],
    port_mapping: bool,
) -> Candidates {
    let reflexive_fut = reflexive_addr(sock, id, local, reflectors);
    // Port mapping is discovered via SSDP and (for PCP) an IPv4 gateway, and yields
    // an IPv4 external address, so skip it for a v6 socket. When enabled it runs
    // concurrently with the reflexive probe — they touch different sockets.
    let ((reflexive, reflexive_rtt), mapped) = if port_mapping && local.is_ipv4() {
        // PCP first, UPnP fallback, in one call.
        let mapped_fut = timeout(
            MAP_TIMEOUT,
            portmap::map_port_auto(local.port(), MAP_LIFETIME, MAP_DESCRIPTION),
        );
        let (reflexive, mapped) = tokio::join!(reflexive_fut, mapped_fut);
        // Only offer the mapping when it fully succeeded within the timeout and
        // its external IP is routable — under double-NAT/CGNAT the gateway can
        // report a private/`100.64/10` address that's useless as a target.
        let mapped = match mapped {
            Ok(Ok(m)) if is_publicly_routable(m.external.ip()) => Some(m.external),
            _ => None,
        };
        (reflexive, mapped)
    } else {
        (reflexive_fut.await, None)
    };

    // Tag each source address with its kind before dedup/cap, so the surviving
    // advertised set can report where each candidate came from.
    let mut kind_of: Vec<(SocketAddr, CandidateKind)> = Vec::with_capacity(3);
    if let Some(m) = mapped {
        kind_of.push((m, CandidateKind::Mapped));
    }
    // Only a reflector that actually answered (RTT present) yields a genuine
    // reflexive candidate; otherwise `reflexive` is just the `local` fallback and
    // `local` below already covers it — don't mislabel it Reflexive.
    if reflexive_rtt.is_some() {
        kind_of.push((reflexive, CandidateKind::Reflexive));
    }
    kind_of.push((local, CandidateKind::Local));

    let mut addrs = Vec::with_capacity(MAX_CANDIDATES);
    for (addr, _) in &kind_of {
        if !addrs.contains(addr) {
            addrs.push(*addr);
        }
    }
    prioritize_and_cap(&mut addrs);
    let kinds = addrs
        .iter()
        .map(|a| {
            let kind = kind_of
                .iter()
                .find(|(x, _)| x == a)
                .map(|(_, k)| *k)
                .unwrap_or(CandidateKind::Local);
            (*a, kind)
        })
        .collect();
    Candidates {
        addrs,
        kinds,
        reflexive_rtt,
        mapped: mapped.is_some(),
    }
}

/// Keep the most-useful [`MAX_CANDIDATES`], best priority first, preserving order
/// within a tier (e.g. mapped before reflexive before local among equally-routable
/// addresses). Applied to our own advertised set and, defensively, to an untrusted
/// peer set — so a routable candidate survives the cap even if the peer
/// front-loaded private/junk addresses.
///
/// Bucketed in a single linear pass rather than sorted: the input can be a large
/// untrusted peer set and we only ever keep a handful, so an attacker can't force
/// an `O(n log n)` sort. Each tier holds at most `MAX_CANDIDATES`, and the scan
/// stops early once tier 0 alone fills the cap (nothing lower could then survive).
fn prioritize_and_cap(addrs: &mut Vec<SocketAddr>) {
    let mut tiers: [Vec<SocketAddr>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for &addr in addrs.iter() {
        let tier = candidate_priority(addr) as usize;
        if tiers[tier].len() < MAX_CANDIDATES {
            tiers[tier].push(addr);
        }
        if tiers[0].len() >= MAX_CANDIDATES {
            break;
        }
    }
    addrs.clear();
    for tier in tiers {
        for addr in tier {
            if addrs.len() < MAX_CANDIDATES {
                addrs.push(addr);
            }
        }
    }
}

/// A candidate's usefulness as a punch target, lower = more preferred:
/// `0` globally routable (reaches a remote peer), `1` LAN-reachable (private /
/// link-local / ULA — useful to a peer behind the same NAT), `2` everything else
/// (loopback, unspecified, CGNAT, multicast, …).
fn candidate_priority(addr: SocketAddr) -> u8 {
    // Rank an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) by its embedded v4 — a
    // peer could otherwise encode a private v4 that way to dodge the v4 tiering.
    let ip = match addr.ip() {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            if is_publicly_routable(IpAddr::V4(v4)) {
                0
            } else if v4.is_private() || v4.is_link_local() {
                1
            } else {
                2
            }
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // 2001:db8::/32 is documentation space — not reachable.
            let documentation = seg[0] == 0x2001 && seg[1] == 0x0db8;
            // `::/96` — the unspecified/loopback addresses AND the obsolete
            // IPv4-compatible form `::a.b.c.d` (RFC 4291), none routable. (The
            // IPv4-*mapped* `::ffff:a.b.c.d` was already unwrapped to v4 above, so
            // it doesn't reach here.) Ranking the whole block junk stops a peer
            // encoding a v4 as `::a.b.c.d` to dodge the v4 tiering.
            let low96_zero = seg[..6].iter().all(|&s| s == 0);
            if v6.is_multicast() || documentation || low96_zero {
                2
            } else if (seg[0] & 0xffc0) == 0xfe80 || (seg[0] & 0xfe00) == 0xfc00 {
                // Stable std has no v6 link-local/ULA predicate, so match by prefix:
                // link-local fe80::/10, unique-local fc00::/7.
                1
            } else {
                // Anything else is treated as globally routable (most v6 is).
                0
            }
        }
    }
}

/// The distinct hosts among a candidate set, preserving order — the set of source
/// IPs a punch may arrive from / should be sprayed toward.
fn candidate_hosts(addrs: &[SocketAddr]) -> Vec<IpAddr> {
    let mut hosts = Vec::new();
    for a in addrs {
        if !hosts.contains(&a.ip()) {
            hosts.push(a.ip());
        }
    }
    hosts
}

/// A conservative "safe to advertise to a peer" check, using only stable std
/// predicates: reject the ranges that clearly can't be reached from off-network.
/// The precise predicates for CGNAT (`100.64.0.0/10`), benchmarking
/// (`198.18.0.0/15`), reserved (`240.0.0.0/4`) — and `is_global` itself — are all
/// still unstable (`feature(ip)`, rust#27709, unstable even on 1.93), so those
/// ranges are matched by hand. CGNAT is the common double-NAT case UPnP surfaces.
fn is_publicly_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            let is_cgnat = a == 100 && (64..=127).contains(&b); // 100.64.0.0/10
            let is_benchmarking = a == 198 && (18..=19).contains(&b); // 198.18.0.0/15
            let is_reserved = a >= 240; // 240.0.0.0/4, reserved/experimental
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_multicast() // 224.0.0.0/4
                && !v4.is_documentation()
                && !v4.is_unspecified()
                && !is_cgnat
                && !is_benchmarking
                && !is_reserved
        }
        // UPnP-IGD yields IPv4 only, so a v6 mapped address can't legitimately
        // occur here. Rather than partially re-implement v6 global-routability
        // with hand-rolled range checks (the stable std predicates don't cover
        // link-local / ULA), refuse to advertise a v6 mapped address at all —
        // maximally conservative, and the branch is unreachable in practice.
        IpAddr::V6(_) => false,
    }
}

/// Discover `sock`'s externally-observed address by asking reflectors to echo
/// the source they see (a STUN-like probe with [`Message::Reflect`]). Returns
/// the first echoed address, or `local` if no reflector answers — correct on an
/// unNATed host, and a NATed host with no reachable reflector can't be punched
/// to anyway. Only a reply from the queried reflector is accepted.
async fn reflexive_addr(
    sock: &UdpSocket,
    id: NodeId,
    local: SocketAddr,
    reflectors: &[SocketAddr],
) -> (SocketAddr, Option<Duration>) {
    let mut buf = [0u8; 128];
    // Distinct per-probe request id (based on this socket's port, so it also
    // differs across concurrent connects). The reflector echoes it in the reply,
    // letting us match a `Reflected` to the probe that elicited it.
    let base_rid = local.port() as u64;
    for (i, &reflector) in reflectors.iter().enumerate() {
        let rid = base_rid.wrapping_add(i as u64);
        let probe = Packet {
            sender: id,
            rid,
            // A reflexive probe comes from a transient data socket, not a routable
            // endpoint — never a routing "server". (A Reflect is excluded from
            // routing on the receiver regardless.)
            reachable: false,
            msg: Message::Reflect,
        }
        .encode();
        let sent = Instant::now();
        if sock.send_to(&probe, reflector).await.is_err() {
            continue;
        }
        // Read until this reflector's window elapses, ignoring stray datagrams,
        // so an unrelated packet arriving first can't cause a false fallback.
        let deadline = sent + REFLECT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break; // window over: try the next reflector
            }
            match timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) if from == reflector => {
                    // Accept only a `Reflected` echoing this probe's rid.
                    if let Ok(Packet {
                        rid: got,
                        msg: Message::Reflected { observed },
                        ..
                    }) = Packet::decode(&buf[..n])
                    {
                        if got == rid {
                            return (observed, Some(sent.elapsed()));
                        }
                    }
                    // Wrong rid or not a Reflected: keep reading this window.
                }
                Ok(Ok(_)) => {}      // stray datagram from elsewhere: keep reading
                Ok(Err(_)) => break, // socket error: try the next reflector
                Err(_) => break,     // window elapsed
            }
        }
    }
    (local, None)
}

/// Dial a peer's candidate addresses on the pre-bound socket, locking onto the
/// first that answers.
async fn punch_direct(sock: UdpSocket, peers: &[SocketAddr], cfg: &PunchConfig) -> Option<Channel> {
    match puncher::connect_to_any(sock, peers, cfg).await {
        Ok(est) => connect_channel(est).await.ok().flatten(),
        Err(_) => None,
    }
}

/// Wait for a punch from any of `peer_hosts` on the pre-bound socket.
async fn punch_accept(
    sock: UdpSocket,
    peer_hosts: &[IpAddr],
    cfg: &PunchConfig,
) -> Option<Channel> {
    match puncher::accept_any(sock, peer_hosts, cfg).await {
        Ok(est) => connect_channel(est).await.ok().flatten(),
        Err(_) => None,
    }
}

/// The Consistent side of a birthday punch: spray random ports at every candidate
/// host in `peer_hosts`.
async fn punch_spray(
    own_host: IpAddr,
    peer_hosts: &[IpAddr],
    cfg: &PunchConfig,
    b: BirthdayParams,
    seed: u64,
) -> Option<Channel> {
    let bind = SocketAddr::new(own_host, 0);
    match puncher::spray_any(bind, peer_hosts, b.range, b.probes, seed, cfg).await {
        Ok(est) => connect_channel(est).await.ok().flatten(),
        Err(_) => None,
    }
}

/// The Random side of a birthday punch: open many sockets and await a probe from
/// any of `peer_hosts`.
async fn punch_open(
    own_host: IpAddr,
    peer_hosts: &[IpAddr],
    cfg: &PunchConfig,
    b: BirthdayParams,
    seed: u64,
) -> Option<Channel> {
    match puncher::open_birthday_sockets_any(own_host, peer_hosts, b.range, b.sockets, seed, cfg)
        .await
    {
        Ok(est) => connect_channel(est).await.ok().flatten(),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lo() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[tokio::test]
    async fn reflexive_addr_learns_the_socket_address() {
        // A reflector node echoes the source it observes; on loopback that's the
        // probe socket's own address, so the discovered address equals it.
        let reflector = Node::bind(lo(), crypto::Keypair::from_seed(&[9u8; 32]))
            .await
            .unwrap();
        let sock = UdpSocket::bind(lo()).await.unwrap();
        let local = sock.local_addr().unwrap();

        let (observed, _rtt) = reflexive_addr(
            &sock,
            NodeId::from_bytes([1u8; 32]),
            local,
            &[reflector.local_addr()],
        )
        .await;
        assert_eq!(
            observed, local,
            "the reflexive probe should learn the socket's own address on loopback"
        );
    }

    #[tokio::test]
    async fn reflexive_addr_falls_back_with_no_reflectors() {
        // No reflector to ask: fall back to the local address.
        let sock = UdpSocket::bind(lo()).await.unwrap();
        let local = sock.local_addr().unwrap();
        let (observed, rtt) =
            reflexive_addr(&sock, NodeId::from_bytes([1u8; 32]), local, &[]).await;
        assert_eq!(observed, local);
        assert_eq!(rtt, None, "no reflector answered, so there's no RTT");
    }

    #[test]
    fn candidate_hosts_dedups_ips_preserving_order() {
        let addrs: Vec<SocketAddr> = ["1.1.1.1:5", "1.1.1.1:6", "2.2.2.2:7"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let hosts = candidate_hosts(&addrs);
        assert_eq!(
            hosts,
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "2.2.2.2".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn candidate_priority_ranks_by_reachability() {
        let p = |s: &str| candidate_priority(s.parse().unwrap());
        // Globally routable → 0.
        assert_eq!(p("8.8.8.8:1"), 0);
        assert_eq!(p("[2606:4700:4700::1111]:1"), 0);
        // LAN-reachable → 1.
        assert_eq!(p("192.168.1.5:1"), 1);
        assert_eq!(p("169.254.1.1:1"), 1);
        assert_eq!(p("[fe80::1]:1"), 1); // link-local
        assert_eq!(p("[fc00::1]:1"), 1); // ULA
                                         // Neither → 2.
        assert_eq!(p("127.0.0.1:1"), 2);
        assert_eq!(p("100.64.0.1:1"), 2); // CGNAT
        assert_eq!(p("[::1]:1"), 2);
        assert_eq!(p("[2001:db8::1]:1"), 2); // v6 documentation, not reachable
        assert_eq!(p("[ff02::1]:1"), 2); // v6 multicast
                                         // IPv4-mapped IPv6 is ranked by its embedded v4, not as generic v6.
        assert_eq!(p("[::ffff:8.8.8.8]:1"), 0); // mapped public v4
        assert_eq!(p("[::ffff:192.168.1.5]:1"), 1); // mapped private v4 → LAN, not 0
                                                    // Obsolete IPv4-compatible IPv6 (::/96) is junk, not routable — a peer
                                                    // can't use it to smuggle a v4 past the tiering.
        assert_eq!(p("[::8.8.8.8]:1"), 2);
        assert_eq!(p("[::192.168.1.5]:1"), 2);
    }

    #[test]
    fn prioritize_and_cap_keeps_routable_past_the_cap() {
        // A set that front-loads junk and buries the one routable candidate: after
        // prioritization the routable one survives the cap, junk is dropped.
        let mut addrs: Vec<SocketAddr> = [
            "127.0.0.1:1",
            "127.0.0.2:2",
            "192.168.0.9:3",
            "10.0.0.9:4",
            "203.0.113.1:5", // TEST-NET (rank 2)
            "8.8.8.8:6",     // the one globally-routable candidate, last
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        prioritize_and_cap(&mut addrs);
        assert_eq!(addrs.len(), MAX_CANDIDATES);
        assert_eq!(
            addrs[0],
            "8.8.8.8:6".parse().unwrap(),
            "routable floats first"
        );
        // The two private/LAN addresses (rank 1) come next, ahead of loopback.
        assert!(addrs.contains(&"192.168.0.9:3".parse().unwrap()));
        assert!(addrs.contains(&"10.0.0.9:4".parse().unwrap()));
    }

    #[test]
    fn public_routability_rejects_unreachable_ranges() {
        let pub_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(is_publicly_routable(pub_ip));
        for bad in [
            "10.0.0.1",             // private
            "192.168.1.1",          // private
            "172.16.0.1",           // private
            "127.0.0.1",            // loopback
            "169.254.1.1",          // link-local
            "100.64.0.1",           // CGNAT
            "203.0.113.1",          // TEST-NET-3 (documentation)
            "224.0.0.1",            // multicast
            "198.18.0.1",           // benchmarking
            "240.0.0.1",            // reserved
            "255.255.255.255",      // broadcast
            "0.0.0.0",              // unspecified
            "::1",                  // v6 loopback
            "2606:4700:4700::1111", // a global v6 — still refused (UPnP is v4-only)
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(!is_publicly_routable(ip), "{bad} must not be advertisable");
        }
    }

    #[tokio::test]
    async fn gather_candidates_falls_back_to_local_with_mapping_off() {
        // With port mapping off and no reflector, the only candidate is `local`
        // (the reflexive probe falls back to it, and the two dedup to one). The
        // mapping-enabled path fires real SSDP, so its mechanics are exercised by
        // portmap's fake-IGD integration test rather than a live multicast here.
        let sock = UdpSocket::bind(lo()).await.unwrap();
        let local = sock.local_addr().unwrap();
        let candidates =
            gather_candidates(&sock, NodeId::from_bytes([1u8; 32]), local, &[], false).await;
        assert_eq!(candidates.addrs, vec![local]);
        assert_eq!(candidates.kinds, vec![(local, CandidateKind::Local)]);
        assert!(!candidates.mapped);
        assert_eq!(candidates.reflexive_rtt, None);
    }

    #[tokio::test]
    async fn gather_candidates_skips_ipv4_only_mapping_for_ipv6_sockets() {
        // UPnP is IPv4-only, so even with mapping enabled a v6 socket must not
        // attempt it (which could advertise an unreachable IPv4 candidate); it
        // stays reflexive-only, yielding just `local` with no reflector.
        let Ok(sock) = UdpSocket::bind("[::1]:0").await else {
            return; // no IPv6 loopback in this environment — nothing to check
        };
        let local = sock.local_addr().unwrap();
        let candidates =
            gather_candidates(&sock, NodeId::from_bytes([1u8; 32]), local, &[], true).await;
        assert_eq!(candidates.addrs, vec![local]);
    }
}
