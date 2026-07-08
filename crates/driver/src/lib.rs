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
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use swarm::dht::{Dht, Event};
use swarm::{Contact, NodeId, QueryId};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

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

    /// Accept one inbound channel. `Ok(None)` means none arrived in time.
    pub async fn accept(self, cfg: &PunchConfig) -> io::Result<Option<Channel>> {
        connect_channel(puncher::accept(self.socket, cfg).await?).await
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

enum Command {
    AddContact(Contact),
    Bootstrap(oneshot::Sender<()>),
    Announce(NodeId, oneshot::Sender<()>),
    Lookup(NodeId, oneshot::Sender<Vec<Contact>>),
    Connect(NodeId, oneshot::Sender<ConnectOutcome>),
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
}

impl Node {
    /// Bind a UDP socket at `bind_addr` and start the node with the given id.
    pub async fn bind(bind_addr: SocketAddr, id: NodeId) -> io::Result<Node> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        tokio::spawn(run(Dht::new(id), socket, cmd_rx));
        Ok(Node {
            id,
            local_addr,
            cmd_tx,
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

    /// Connect to `target` by id, coordinated over the DHT.
    pub async fn connect(&self, target: NodeId) -> Result<ConnectOutcome> {
        self.request(|tx| Command::Connect(target, tx)).await
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
async fn run(mut dht: Dht, socket: UdpSocket, mut cmd_rx: mpsc::Receiver<Command>) {
    let start = Instant::now();
    let now = || start.elapsed().as_millis() as u64;
    let mut buf = vec![0u8; RECV_BUF];

    // Bootstrap waiters are keyed by the query id so a stray QueryFinished can't
    // resolve them and concurrent bootstraps don't clobber each other. The other
    // ops keep a list of waiters per key: a second caller for an in-flight key
    // joins the existing operation rather than starting (and overwriting) a
    // duplicate.
    let mut pending_bootstrap: HashMap<QueryId, oneshot::Sender<()>> = HashMap::new();
    let mut pending_announce: HashMap<NodeId, Vec<oneshot::Sender<()>>> = HashMap::new();
    let mut pending_lookup: HashMap<NodeId, Vec<oneshot::Sender<Vec<Contact>>>> = HashMap::new();
    let mut pending_connect: HashMap<NodeId, Vec<oneshot::Sender<ConnectOutcome>>> = HashMap::new();

    loop {
        // Flush everything the core wants to send. A dropped datagram is fine:
        // this is best-effort UDP and the DHT tolerates loss via query/connect
        // timeouts, so we don't tear the node down on a transient send error.
        while let Some(t) = dht.poll_transmit() {
            let _ = socket.send_to(&t.data, t.to).await;
        }
        // Deliver completed operations back to every awaiting caller.
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
                Event::Connected { target, outcome } => {
                    for tx in pending_connect.remove(&target).unwrap_or_default() {
                        let _ = tx.send(outcome);
                    }
                }
            }
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
                        let waiters = pending_connect.entry(target).or_default();
                        let first = waiters.is_empty();
                        waiters.push(tx);
                        if first {
                            dht.connect(target, now());
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
