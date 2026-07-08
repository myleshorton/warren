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

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use swarm::dht::{Dht, Event};
use swarm::{Contact, NodeId, QueryId};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};

pub use puncher::Config as PunchConfig;
pub use swarm::dht::ConnectOutcome;

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
/// `channel` is `None` when the target wasn't found, signaling timed out, the
/// path is `Relayed` (no direct data path yet — future work), or the punch to an
/// otherwise-reachable peer didn't complete in time.
#[derive(Debug)]
pub struct Connection {
    /// How the DHT resolved the connection.
    pub outcome: ConnectOutcome,
    /// The established data channel, if one was punched.
    pub channel: Option<Channel>,
}

enum Command {
    AddContact(Contact),
    Bootstrap(oneshot::Sender<()>),
    Announce(NodeId, oneshot::Sender<()>),
    Lookup(NodeId, oneshot::Sender<Vec<Contact>>),
    Connect(NodeId, oneshot::Sender<Connection>),
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

impl Node {
    /// Bind a UDP socket at `bind_addr` and start the node with the given id.
    pub async fn bind(bind_addr: SocketAddr, id: NodeId) -> io::Result<Node> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        tokio::spawn(run(Dht::new(id), socket, cmd_rx, incoming_tx));
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

    /// Connect to `target` by id, coordinated over the DHT: discover it, broker
    /// signaling through a coordinator, and punch a data channel — all from one
    /// call. The returned [`Connection`] carries the reachability outcome and the
    /// live [`Channel`] when the punch succeeds.
    pub async fn connect(&self, target: NodeId) -> Result<Connection> {
        self.request(|tx| Command::Connect(target, tx)).await
    }

    /// Await the next channel opened by a peer that connected *to us*. The peer
    /// side of [`Node::connect`]: a node that has announced itself surfaces each
    /// inbound channel here. Waits until one is punched (or [`Closed`] if the
    /// node shuts down).
    pub async fn next_incoming(&self) -> Result<Channel> {
        self.incoming.lock().await.recv().await.ok_or(Closed)
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
    // Timing for the actual hole punch once the DHT has brokered reachability.
    let punch_cfg = PunchConfig::default();

    // Bootstrap waiters are keyed by the query id so a stray QueryFinished can't
    // resolve them and concurrent bootstraps don't clobber each other. Announce
    // and lookup keep a list of waiters per key: a second caller for an in-flight
    // key joins the existing operation rather than starting a duplicate.
    let mut pending_bootstrap: HashMap<QueryId, oneshot::Sender<()>> = HashMap::new();
    let mut pending_announce: HashMap<NodeId, Vec<oneshot::Sender<()>>> = HashMap::new();
    let mut pending_lookup: HashMap<NodeId, Vec<oneshot::Sender<Vec<Contact>>>> = HashMap::new();
    // A connect holds a pre-bound data socket (whose address is advertised to the
    // peer) until reachability resolves, then punches on it. One connect per
    // target at a time: a second overwrites the first (whose waiter sees Closed).
    let mut pending_connect: HashMap<NodeId, (UdpSocket, oneshot::Sender<Connection>)> =
        HashMap::new();

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
                } => {
                    if let Some((data_sock, tx)) = pending_connect.remove(&target) {
                        spawn_connect_punch(data_sock, outcome, peer_data_addr, punch_cfg, tx);
                    }
                }
                Event::IncomingConnect {
                    initiator,
                    initiator_data_addr,
                    ..
                } => {
                    // Stand up a data socket, tell the core where to punch back,
                    // and accept a punch from the initiator on it.
                    if let Ok(data_sock) = UdpSocket::bind(SocketAddr::new(data_ip, 0)).await {
                        if let Ok(data_addr) = data_sock.local_addr() {
                            dht.accept_connect(initiator, data_addr);
                            spawn_accept_punch(
                                data_sock,
                                initiator_data_addr.ip(),
                                punch_cfg,
                                incoming_tx.clone(),
                            );
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
                    Some(Command::Connect(target, tx)) => {
                        // Bind the data socket up front: its address is what the
                        // target learns to punch back to. On bind failure we drop
                        // the waiter (caller sees Closed).
                        if let Ok(data_sock) = UdpSocket::bind(SocketAddr::new(data_ip, 0)).await {
                            if let Ok(data_addr) = data_sock.local_addr() {
                                pending_connect.insert(target, (data_sock, tx));
                                dht.connect(target, data_addr, now());
                            }
                        }
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

/// Punch a data channel to the peer that a `connect` resolved, then report the
/// [`Connection`] to the waiting caller. Runs in its own task so the punch's
/// wait doesn't block the actor loop. Only the directly-punchable outcomes dial
/// the peer's data socket; `Relayed`/`NotFound`/`TimedOut` report no channel.
fn spawn_connect_punch(
    data_sock: UdpSocket,
    outcome: ConnectOutcome,
    peer_data_addr: Option<SocketAddr>,
    cfg: PunchConfig,
    tx: oneshot::Sender<Connection>,
) {
    tokio::spawn(async move {
        let channel = match (outcome, peer_data_addr) {
            (ConnectOutcome::Direct | ConnectOutcome::Punched, Some(peer)) => {
                match puncher::connect_to(data_sock, peer, &cfg).await {
                    Ok(est) => connect_channel(est).await.ok().flatten(),
                    Err(_) => None,
                }
            }
            _ => None,
        };
        let _ = tx.send(Connection { outcome, channel });
    });
}

/// Accept a punch from `peer_host` on `data_sock` and, on success, hand the
/// channel to the node's incoming stream. Runs in its own task for the same
/// reason as [`spawn_connect_punch`].
fn spawn_accept_punch(
    data_sock: UdpSocket,
    peer_host: IpAddr,
    cfg: PunchConfig,
    incoming_tx: mpsc::Sender<Channel>,
) {
    tokio::spawn(async move {
        if let Ok(est) = puncher::accept(data_sock, peer_host, &cfg).await {
            if let Ok(Some(channel)) = connect_channel(est).await {
                let _ = incoming_tx.send(channel).await;
            }
        }
    });
}
