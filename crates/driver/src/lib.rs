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
//! use swarm::NodeId;
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let addr = "127.0.0.1:0".parse().unwrap();
//! let node = Node::bind(addr, NodeId::from_bytes([7u8; 32])).await?;
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

/// All timing/parameter tuning for the hole punch a connect performs once the
/// DHT has brokered reachability.
#[derive(Debug, Clone, Copy, Default)]
pub struct PunchTuning {
    /// Timing knobs (deadline, probe interval) for every punch primitive.
    pub config: PunchConfig,
    /// Birthday-punch parameters for the symmetric-NAT (`Punched`) path.
    pub birthday: BirthdayParams,
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
#[derive(Debug)]
pub struct Connection {
    /// How the DHT resolved the connection.
    pub outcome: ConnectOutcome,
    /// The established data channel, if one was punched.
    pub channel: Option<Channel>,
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
    Connect(NodeId, UdpSocket, SocketAddr, oneshot::Sender<ConnectReply>),
    SetFirewall(Firewall),
    Reflectors(oneshot::Sender<Vec<SocketAddr>>),
}

/// A handle to a running DHT node backed by a real UDP socket.
///
/// Cloneable: all clones drive the same underlying node. When the last handle is
/// dropped, the node's task shuts down.
#[derive(Clone)]
pub struct Node {
    id: NodeId,
    local_addr: SocketAddr,
    cmd_tx: mpsc::Sender<Command>,
    /// Channels punched in response to inbound connects, delivered by the actor.
    /// Shared behind a mutex so cloned handles share the single stream (accept is
    /// naturally one consumer); [`Node::next_incoming`] drains it.
    incoming: Arc<Mutex<mpsc::Receiver<Channel>>>,
}

/// A running periodic re-announce started by [`Node::keep_announced`]. Hold it
/// for as long as the content should stay discoverable; dropping it stops the
/// loop. (Announce records don't expire on their own, so a long-lived provider
/// re-announces both to survive DHT churn — the closest-K set near a topic
/// changes as peers come and go — and to follow a topic that rotates by epoch.)
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
    /// Bind a UDP socket at `bind_addr` and start the node with the given id,
    /// using default punch tuning.
    pub async fn bind(bind_addr: SocketAddr, id: NodeId) -> io::Result<Node> {
        Node::bind_with(bind_addr, id, PunchTuning::default()).await
    }

    /// Like [`Node::bind`], but with explicit punch tuning — chiefly to shrink
    /// the birthday port range for fast, reliable loopback tests.
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the birthday port range is
    /// invalid (`start` must satisfy `1 <= start < end`) — validated here so a
    /// bad range fails at construction rather than panicking the node's task
    /// when a `Punched` connect later invokes the spray/open primitives.
    pub async fn bind_with(
        bind_addr: SocketAddr,
        id: NodeId,
        tuning: PunchTuning,
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
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        tokio::spawn(run(Dht::new(id), socket, cmd_rx, incoming_tx, tuning));
        Ok(Node {
            id,
            local_addr,
            cmd_tx,
            incoming: Arc::new(Mutex::new(incoming_rx)),
        })
    }

    /// This node's id.
    pub fn id(&self) -> NodeId {
        self.id
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
        // Learn the data socket's external mapping from a reflector; falls back to
        // `local` if none answers (correct on an unNATed host).
        let reflectors = self.reflectors().await.map_err(|_| ConnectError::Closed)?;
        let advertised = reflexive_addr(&data_sock, self.id, local, &reflectors).await;
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Connect(target, data_sock, advertised, tx))
            .await
            .map_err(|_| ConnectError::Closed)?;
        match rx.await {
            Ok(Ok(conn)) => Ok(conn),
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

/// The node's event loop: owns the `Dht`, the socket, and the pending-op maps.
async fn run(
    mut dht: Dht,
    socket: UdpSocket,
    mut cmd_rx: mpsc::Receiver<Command>,
    incoming_tx: mpsc::Sender<Channel>,
    tuning: PunchTuning,
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
    let mut pending_connect: HashMap<NodeId, (UdpSocket, oneshot::Sender<ConnectReply>)> =
        HashMap::new();
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
                    peer_data_addr,
                    strategy,
                } => {
                    if let Some((data_sock, tx)) = pending_connect.remove(&target) {
                        // Seed the birthday RNG from the pre-bound socket's port so
                        // concurrent connects don't spray identical port sequences.
                        let seed = data_sock.local_addr().map(|a| a.port()).unwrap_or(0) as u64;
                        spawn_connect_punch(PunchJob {
                            data_sock,
                            own_host: data_ip,
                            peer: peer_data_addr,
                            strategy,
                            outcome,
                            cfg: punch_cfg,
                            birthday,
                            seed,
                            tx,
                        });
                    }
                }
                Event::IncomingConnect {
                    initiator,
                    initiator_data_addr,
                    strategy,
                } => {
                    // Stand up a data socket and discover its external address via
                    // a reflexive probe — off the actor (it awaits a round-trip),
                    // feeding the result back so we then reply with that address
                    // and run the punch (see the `reflexive_rx` branch below).
                    // Decline if the node is bound to an unspecified address: the
                    // data socket's address would be unspecified too, unpunchable
                    // by the peer (mirrors the outbound `UnspecifiedLocalAddr`
                    // check); the initiator times out.
                    if !data_ip.is_unspecified() {
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
                                    peer_host: initiator_data_addr.ip(),
                                    strategy,
                                    seed: local.port() as u64,
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

        // Sleep until the core's next deadline (or forever if it has none).
        let delay = dht
            .poll_timeout()
            .map(|deadline| Duration::from_millis(deadline.saturating_sub(now())));

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
                    Some(Command::Connect(target, data_sock, data_addr, tx)) => {
                        // The socket is already bound by `Node::connect`. Only one
                        // connect per target at a time; reject a second rather than
                        // displace the in-flight one's waiter.
                        match pending_connect.entry(target) {
                            Entry::Occupied(_) => {
                                let _ = tx.send(Err(()));
                            }
                            Entry::Vacant(slot) => {
                                slot.insert((data_sock, tx));
                                dht.connect(target, data_addr, now());
                            }
                        }
                    }
                    Some(Command::SetFirewall(fw)) => dht.set_firewall(fw),
                    Some(Command::Reflectors(tx)) => {
                        let id = dht.id();
                        let addrs = dht.closest(&id, REFLECTORS).into_iter().map(|c| c.addr).collect();
                        let _ = tx.send(addrs);
                    }
                }
            }
            recv = socket.recv_from(&mut buf) => {
                match recv {
                    Ok((n, from)) => dht.handle_input(from, &buf[..n], now()),
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
                    // initiator with the discovered external address, then run the
                    // punch on the data socket per the planned strategy.
                    dht.accept_connect(done.initiator, done.external_addr, now());
                    spawn_accept_punch(AcceptJob {
                        data_sock: done.data_sock,
                        own_host: data_ip,
                        peer_host: done.peer_host,
                        strategy: done.strategy,
                        cfg: punch_cfg,
                        birthday,
                        seed: done.seed,
                        incoming_tx: incoming_tx.clone(),
                    });
                }
            }
            _ = async {
                match &delay {
                    Some(d) => tokio::time::sleep(*d).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
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
    /// The peer's data address (its host is what we punch toward).
    peer: Option<SocketAddr>,
    /// Our punch role, as planned by the core.
    strategy: Option<Strategy>,
    /// The reachability outcome to report alongside any channel.
    outcome: ConnectOutcome,
    cfg: PunchConfig,
    birthday: BirthdayParams,
    seed: u64,
    tx: oneshot::Sender<ConnectReply>,
}

/// The reachable side of a punch after an `IncomingConnect`.
struct AcceptJob {
    data_sock: UdpSocket,
    own_host: IpAddr,
    /// The initiator's data host, the only source we accept a punch from.
    peer_host: IpAddr,
    strategy: Strategy,
    cfg: PunchConfig,
    birthday: BirthdayParams,
    seed: u64,
    incoming_tx: mpsc::Sender<Channel>,
}

/// Inputs to an accept-side reflexive probe task.
struct ReflexiveProbe {
    data_sock: UdpSocket,
    id: NodeId,
    local: SocketAddr,
    reflectors: Vec<SocketAddr>,
    initiator: NodeId,
    peer_host: IpAddr,
    strategy: Strategy,
    seed: u64,
    done: mpsc::Sender<ReflexiveDone>,
}

/// Result of an accept-side reflexive probe, fed back into the actor loop.
struct ReflexiveDone {
    initiator: NodeId,
    /// The data socket's externally-observed address (or its local address if no
    /// reflector answered), to advertise to the initiator.
    external_addr: SocketAddr,
    data_sock: UdpSocket,
    peer_host: IpAddr,
    strategy: Strategy,
    seed: u64,
}

/// Discover the accept-side data socket's external address off the actor, then
/// hand it (and the socket) back so the actor can reply and punch. Runs in its
/// own task because the probe awaits a reflector round-trip.
fn spawn_reflexive_probe(p: ReflexiveProbe) {
    tokio::spawn(async move {
        let external_addr = reflexive_addr(&p.data_sock, p.id, p.local, &p.reflectors).await;
        let _ = p
            .done
            .send(ReflexiveDone {
                initiator: p.initiator,
                external_addr,
                data_sock: p.data_sock,
                peer_host: p.peer_host,
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
        peer,
        strategy,
        outcome,
        cfg,
        birthday,
        seed,
        tx,
    } = job;
    tokio::spawn(async move {
        let channel = match (strategy, peer) {
            (Some(Strategy::Direct), Some(peer)) => punch_direct(data_sock, peer, &cfg).await,
            (Some(Strategy::SprayRandomPorts), Some(peer)) => {
                // The birthday primitives bind their own sockets; free the
                // pre-bound one now so its FD/port can't collide with them.
                drop(data_sock);
                punch_spray(own_host, peer.ip(), &cfg, birthday, seed).await
            }
            (Some(Strategy::OpenBirthdaySockets), Some(peer)) => {
                drop(data_sock);
                punch_open(own_host, peer.ip(), &cfg, birthday, seed).await
            }
            // Relay (symmetric↔symmetric: no direct path, and relaying is not
            // built by design) / no peer to punch to.
            _ => {
                drop(data_sock);
                None
            }
        };
        let _ = tx.send(Ok(Connection { outcome, channel }));
    });
}

/// Accept a punch from the initiator per its planned strategy and, on success,
/// hand the channel to the node's incoming stream. Runs in its own task for the
/// same reason as [`spawn_connect_punch`].
fn spawn_accept_punch(job: AcceptJob) {
    let AcceptJob {
        data_sock,
        own_host,
        peer_host,
        strategy,
        cfg,
        birthday,
        seed,
        incoming_tx,
    } = job;
    tokio::spawn(async move {
        let channel = match strategy {
            Strategy::Direct => punch_accept(data_sock, peer_host, &cfg).await,
            Strategy::SprayRandomPorts => {
                // Birthday primitives bind their own sockets (see connect side).
                drop(data_sock);
                punch_spray(own_host, peer_host, &cfg, birthday, seed).await
            }
            Strategy::OpenBirthdaySockets => {
                drop(data_sock);
                punch_open(own_host, peer_host, &cfg, birthday, seed).await
            }
            Strategy::Relay => {
                drop(data_sock);
                None
            }
        };
        if let Some(channel) = channel {
            // Non-blocking: if the application isn't draining `next_incoming`
            // (queue full), drop this channel rather than park the task holding
            // its socket. A flood of inbound connects is shed at the queue bound
            // instead of accumulating blocked tasks; the peer can retry.
            let _ = incoming_tx.try_send(channel);
        }
    });
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
) -> SocketAddr {
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
            msg: Message::Reflect,
        }
        .encode();
        if sock.send_to(&probe, reflector).await.is_err() {
            continue;
        }
        // Read until this reflector's window elapses, ignoring stray datagrams,
        // so an unrelated packet arriving first can't cause a false fallback.
        let deadline = Instant::now() + REFLECT_TIMEOUT;
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
                            return observed;
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
    local
}

/// Dial a reachable peer on the pre-bound socket.
async fn punch_direct(sock: UdpSocket, peer: SocketAddr, cfg: &PunchConfig) -> Option<Channel> {
    match puncher::connect_to(sock, peer, cfg).await {
        Ok(est) => connect_channel(est).await.ok().flatten(),
        Err(_) => None,
    }
}

/// Wait for a punch from `peer_host` on the pre-bound socket.
async fn punch_accept(sock: UdpSocket, peer_host: IpAddr, cfg: &PunchConfig) -> Option<Channel> {
    match puncher::accept(sock, peer_host, cfg).await {
        Ok(est) => connect_channel(est).await.ok().flatten(),
        Err(_) => None,
    }
}

/// The Consistent side of a birthday punch: spray random ports at `peer_host`.
async fn punch_spray(
    own_host: IpAddr,
    peer_host: IpAddr,
    cfg: &PunchConfig,
    b: BirthdayParams,
    seed: u64,
) -> Option<Channel> {
    let bind = SocketAddr::new(own_host, 0);
    match puncher::spray(bind, peer_host, b.range, b.probes, seed, cfg).await {
        Ok(est) => connect_channel(est).await.ok().flatten(),
        Err(_) => None,
    }
}

/// The Random side of a birthday punch: open many sockets and await a probe.
async fn punch_open(
    own_host: IpAddr,
    peer_host: IpAddr,
    cfg: &PunchConfig,
    b: BirthdayParams,
    seed: u64,
) -> Option<Channel> {
    match puncher::open_birthday_sockets(own_host, peer_host, b.range, b.sockets, seed, cfg).await {
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
        let reflector = Node::bind(lo(), NodeId::from_bytes([9u8; 32]))
            .await
            .unwrap();
        let sock = UdpSocket::bind(lo()).await.unwrap();
        let local = sock.local_addr().unwrap();

        let observed = reflexive_addr(
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
        let observed = reflexive_addr(&sock, NodeId::from_bytes([1u8; 32]), local, &[]).await;
        assert_eq!(observed, local);
    }
}
