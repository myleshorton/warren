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
//! # async fn ex() -> std::io::Result<()> {
//! let addr = "127.0.0.1:0".parse().unwrap();
//! let node = Node::bind(addr, NodeId::from_bytes([7u8; 32])).await?;
//! node.bootstrap().await;
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use swarm::dht::{ConnectOutcome, Dht, Event};
use swarm::{Contact, NodeId};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

/// Largest datagram we read. A `Nodes` reply (up to `K` contacts + `K` peers at
/// ~39 bytes each) fits comfortably inside this.
const RECV_BUF: usize = 4096;

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
    pub async fn add_contact(&self, contact: Contact) {
        let _ = self.cmd_tx.send(Command::AddContact(contact)).await;
    }

    /// Bootstrap (self-lookup) and wait for it to settle.
    pub async fn bootstrap(&self) {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::Bootstrap(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Announce this node under `topic` and wait for the announce to complete.
    pub async fn announce(&self, topic: NodeId) {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::Announce(topic, tx)).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Look up peers announced under `topic`.
    pub async fn lookup(&self, topic: NodeId) -> Vec<Contact> {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Command::Lookup(topic, tx)).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Connect to `target` by id, coordinated over the DHT.
    pub async fn connect(&self, target: NodeId) -> ConnectOutcome {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(Command::Connect(target, tx))
            .await
            .is_err()
        {
            return ConnectOutcome::TimedOut;
        }
        rx.await.unwrap_or(ConnectOutcome::TimedOut)
    }
}

/// The node's event loop: owns the `Dht`, the socket, and the pending-op maps.
async fn run(mut dht: Dht, socket: UdpSocket, mut cmd_rx: mpsc::Receiver<Command>) {
    let start = Instant::now();
    let now = || start.elapsed().as_millis() as u64;
    let mut buf = vec![0u8; RECV_BUF];

    let mut pending_bootstrap: Option<oneshot::Sender<()>> = None;
    let mut pending_announce: HashMap<NodeId, oneshot::Sender<()>> = HashMap::new();
    let mut pending_lookup: HashMap<NodeId, oneshot::Sender<Vec<Contact>>> = HashMap::new();
    let mut pending_connect: HashMap<NodeId, oneshot::Sender<ConnectOutcome>> = HashMap::new();

    loop {
        // Flush everything the core wants to send.
        while let Some(t) = dht.poll_transmit() {
            let _ = socket.send_to(&t.data, t.to).await;
        }
        // Deliver completed operations back to their awaiting callers.
        while let Some(ev) = dht.poll_event() {
            match ev {
                Event::QueryFinished { .. } => {
                    if let Some(tx) = pending_bootstrap.take() {
                        let _ = tx.send(());
                    }
                }
                Event::LookupFinished { topic, peers } => {
                    if let Some(tx) = pending_lookup.remove(&topic) {
                        let _ = tx.send(peers);
                    }
                }
                Event::AnnounceFinished { topic } => {
                    if let Some(tx) = pending_announce.remove(&topic) {
                        let _ = tx.send(());
                    }
                }
                Event::Connected { target, outcome } => {
                    if let Some(tx) = pending_connect.remove(&target) {
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
                        pending_bootstrap = Some(tx);
                        dht.bootstrap(now());
                    }
                    Some(Command::Announce(topic, tx)) => {
                        pending_announce.insert(topic, tx);
                        dht.announce(topic, now());
                    }
                    Some(Command::Lookup(topic, tx)) => {
                        pending_lookup.insert(topic, tx);
                        dht.lookup(topic, now());
                    }
                    Some(Command::Connect(target, tx)) => {
                        pending_connect.insert(target, tx);
                        dht.connect(target, now());
                    }
                }
            }
            recv = socket.recv_from(&mut buf) => {
                if let Ok((n, from)) = recv {
                    dht.handle_input(from, &buf[..n], now());
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
