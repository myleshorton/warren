//! Deterministic in-memory network simulator for the [`Dht`] core.
//!
//! Because [`Dht`] is sans-IO, we can run many nodes against a virtual clock
//! with a fully controlled network and get **repeatable, flake-free** results:
//! packet delivery is scheduled in a priority queue keyed by `(time, seq)`, so
//! ordering is deterministic, and all randomness comes from a seeded PRNG. This
//! is the primary way DHT behavior is verified before any real socket exists.

use crate::dht::{Dht, Event, Millis, QueryId};
use crate::id::{NodeId, ID_LEN};
use crate::nat::Firewall;
use crate::routing::Contact;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// Small, fast, seedable PRNG (SplitMix64). Deterministic across platforms.
#[derive(Clone)]
pub struct Rng(u64);

impl Rng {
    /// Seed the generator.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A random node id.
    pub fn node_id(&mut self) -> NodeId {
        NodeId::from_bytes(self.fill32())
    }

    /// A random 32-byte buffer, drawn deterministically from the PRNG — the seed
    /// material for a node id or a [`crypto::Keypair`].
    pub fn fill32(&mut self) -> [u8; ID_LEN] {
        let mut b = [0u8; ID_LEN];
        for chunk in b.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        b
    }

    /// A deterministic Ed25519 identity keypair, so tests that now bind a node
    /// with a [`crypto::Keypair`] (rather than a bare [`NodeId`]) stay reproducible.
    /// The node's id is derived from this keypair's public key (see `driver::Node`).
    pub fn keypair(&mut self) -> crypto::Keypair {
        crypto::Keypair::from_seed(&self.fill32())
    }

    /// A float in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The NAT a simulated node sits behind.
///
/// This is a minimal model covering the signal NAT *classification* depends on:
/// what source address a receiver observes. Full data-plane translation with
/// inbound admission/filtering (needed to exercise real punch delivery) arrives
/// with the NAT-translating packet simulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatKind {
    /// Publicly reachable; stable observed address, unsolicited inbound works.
    Open,
    /// Firewalled but stable observed port (endpoint-independent mapping).
    Consistent,
    /// Symmetric: a fresh observed port per destination.
    Random,
}

struct Node {
    dht: Dht,
    addr: SocketAddr,
    nat: NatKind,
}

enum Scheduled {
    Deliver {
        to: usize,
        from: SocketAddr,
        data: Vec<u8>,
    },
}

struct Slot {
    time: Millis,
    seq: u64,
    item: Scheduled,
}

impl PartialEq for Slot {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time && self.seq == other.seq
    }
}
impl Eq for Slot {}
impl PartialOrd for Slot {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Slot {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.time.cmp(&other.time).then(self.seq.cmp(&other.seq))
    }
}

/// A deterministic network of DHT nodes sharing one virtual clock.
pub struct Sim {
    now: Millis,
    nodes: Vec<Node>,
    by_addr: HashMap<SocketAddr, usize>,
    /// Reverse map from a NAT-translated source address back to its node, so a
    /// reply addressed to an observed (translated) address routes home.
    nat_reverse: HashMap<SocketAddr, usize>,
    queue: BinaryHeap<Reverse<Slot>>,
    seq: u64,
    latency_ms: Millis,
    loss: f64,
    seed: u64,
    rng: Rng,
    /// Nodes that have gone "offline": packets to them are dropped.
    disabled: HashSet<usize>,
    events: Vec<(usize, Event)>,
}

impl Sim {
    /// Create a simulator with a fixed one-way latency and a seed.
    pub fn new(latency_ms: Millis, seed: u64) -> Self {
        Self {
            now: 0,
            nodes: Vec::new(),
            by_addr: HashMap::new(),
            nat_reverse: HashMap::new(),
            queue: BinaryHeap::new(),
            seq: 0,
            latency_ms,
            loss: 0.0,
            seed,
            rng: Rng::new(seed),
            disabled: HashSet::new(),
            events: Vec::new(),
        }
    }

    /// Set the packet loss probability in `[0, 1)`.
    pub fn set_loss(&mut self, loss: f64) {
        self.loss = loss;
    }

    /// Take a node fully offline: packets both to and from it are dropped,
    /// modeling a peer that has left the network. (Its internal timers may still
    /// fire, but nothing it produces reaches the wire.)
    pub fn disable_node(&mut self, i: usize) {
        self.disabled.insert(i);
    }

    /// Borrow the simulator's PRNG (e.g. to mint node ids).
    pub fn rng(&mut self) -> &mut Rng {
        &mut self.rng
    }

    /// The current virtual time.
    pub fn now(&self) -> Millis {
        self.now
    }

    /// Add a node with the given id; returns its index and assigned address.
    pub fn add_node(&mut self, id: NodeId) -> (usize, SocketAddr) {
        let index = self.nodes.len();
        let addr = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 1),
            10_000 + index as u16,
        ));
        self.nodes.push(Node {
            dht: Dht::new(id),
            addr,
            nat: NatKind::Open,
        });
        self.by_addr.insert(addr, index);
        (index, addr)
    }

    /// Set the NAT a node sits behind (default [`NatKind::Open`]).
    ///
    /// Also updates the node's declared firewall so connect signaling reports
    /// the same type the sim routes it as.
    pub fn set_nat(&mut self, i: usize, kind: NatKind) {
        self.nodes[i].nat = kind;
        let fw = match kind {
            NatKind::Open => Firewall::Open,
            NatKind::Consistent => Firewall::Consistent,
            NatKind::Random => Firewall::Random,
        };
        self.nodes[i].dht.set_firewall(fw);
    }

    /// Announce node `i` under `topic`.
    pub fn announce(&mut self, i: usize, topic: NodeId) -> QueryId {
        let now = self.now;
        self.nodes[i].dht.announce(topic, now)
    }

    /// Look up announcers of `topic` from node `i`.
    pub fn lookup(&mut self, i: usize, topic: NodeId) -> QueryId {
        let now = self.now;
        self.nodes[i].dht.lookup(topic, now)
    }

    /// Connect node `i` to `target`, coordinated through the DHT. The sim has no
    /// separate data sockets, so a node advertises its own DHT address as its
    /// data address, and auto-accepts inbound connects as they surface.
    pub fn connect(&mut self, i: usize, target: NodeId) -> QueryId {
        let now = self.now;
        let data_addr = self.nodes[i].addr;
        self.nodes[i].dht.connect(target, vec![data_addr], now)
    }

    /// The NAT a node sits behind.
    pub fn nat_kind(&self, i: usize) -> NatKind {
        self.nodes[i].nat
    }

    /// Have node `i` sample its NAT by probing up to `count` known peers.
    ///
    /// Reachability (which distinguishes Open from Consistent) is supplied from
    /// the node's modeled NAT, standing in for the inbound firewall probe.
    pub fn sample_nat(&mut self, i: usize, count: usize) {
        let now = self.now;
        let reachable = self.nodes[i].nat == NatKind::Open;
        self.nodes[i].dht.note_reachable(reachable);
        self.nodes[i].dht.sample_nat(now, count);
    }

    /// The source address a receiver observes for a packet `sender` -> `dest`.
    ///
    /// Stable for Open/Consistent; per-destination for Random. Random ports live
    /// well above the real-address block so they cannot collide with it.
    fn translated_source(&self, sender: usize, dest: usize) -> SocketAddr {
        match self.nodes[sender].nat {
            NatKind::Open | NatKind::Consistent => self.nodes[sender].addr,
            NatKind::Random => {
                let host = self.nodes[sender].addr.ip();
                let mut r = Rng::new(self.seed ^ ((sender as u64) << 32) ^ dest as u64);
                let port = 30_000 + (r.next_u64() % 30_000) as u16;
                SocketAddr::new(host, port)
            }
        }
    }

    /// Resolve a destination address to a node, via the direct map or the NAT
    /// reverse map (so replies to observed addresses route home).
    fn resolve(&self, addr: &SocketAddr) -> Option<usize> {
        self.by_addr
            .get(addr)
            .copied()
            .or_else(|| self.nat_reverse.get(addr).copied())
    }

    /// Address of node `i`.
    pub fn addr(&self, i: usize) -> SocketAddr {
        self.nodes[i].addr
    }

    /// Immutable access to node `i`'s DHT.
    pub fn dht(&self, i: usize) -> &Dht {
        &self.nodes[i].dht
    }

    /// Mutable access to node `i`'s DHT.
    pub fn dht_mut(&mut self, i: usize) -> &mut Dht {
        &mut self.nodes[i].dht
    }

    /// Start a lookup on node `i` at the current time.
    pub fn find_node(&mut self, i: usize, target: NodeId) -> QueryId {
        let now = self.now;
        self.nodes[i].dht.find_node(target, now)
    }

    /// Start a self-lookup (bootstrap) on node `i`.
    pub fn bootstrap(&mut self, i: usize) -> QueryId {
        let now = self.now;
        self.nodes[i].dht.bootstrap(now)
    }

    /// Drain and return all collected `(node_index, event)` pairs.
    pub fn take_events(&mut self) -> Vec<(usize, Event)> {
        std::mem::take(&mut self.events)
    }

    fn drain_outboxes(&mut self) {
        for i in 0..self.nodes.len() {
            // An offline node's outbound is drained and discarded, so it neither
            // sends nor receives.
            let sender_offline = self.disabled.contains(&i);
            while let Some(t) = self.nodes[i].dht.poll_transmit() {
                if sender_offline {
                    continue;
                }
                let Some(to) = self.resolve(&t.to) else {
                    continue; // unknown destination: dropped, as on a real net
                };
                if self.disabled.contains(&to) {
                    continue; // recipient is offline
                }
                if self.loss > 0.0 && self.rng.unit() < self.loss {
                    continue; // simulated packet loss
                }
                // The receiver sees our NAT-translated source, not our raw addr.
                let from = self.translated_source(i, to);
                if from != self.nodes[i].addr {
                    self.nat_reverse.insert(from, i);
                }
                let time = self.now + self.latency_ms;
                self.queue.push(Reverse(Slot {
                    time,
                    seq: self.seq,
                    item: Scheduled::Deliver {
                        to,
                        from,
                        data: t.data,
                    },
                }));
                self.seq += 1;
            }
        }
    }

    fn collect_events(&mut self) {
        for i in 0..self.nodes.len() {
            while let Some(e) = self.nodes[i].dht.poll_event() {
                // Auto-accept incoming connects, advertising the node's own DHT
                // address as its data address (the sim has no separate data
                // sockets). This models a node that always accepts and lets
                // connect signaling complete; the event is still recorded so
                // tests can inspect it.
                if let Event::IncomingConnect { initiator, .. } = &e {
                    let initiator = *initiator;
                    let data_addr = self.nodes[i].addr;
                    let now = self.now;
                    self.nodes[i]
                        .dht
                        .accept_connect(initiator, vec![data_addr], now);
                }
                self.events.push((i, e));
            }
        }
    }

    /// Run until no packets are in flight and no timers are pending, or until
    /// `max_steps` iterations elapse (a guard against a misbehaving core).
    ///
    /// Returns the number of steps taken.
    pub fn run(&mut self, max_steps: usize) -> usize {
        let mut steps = 0;
        loop {
            // Collect events before draining: handling an `IncomingConnect` here
            // auto-accepts and queues the reply into the node's outbox, so the
            // drain must run *after* to schedule it — otherwise the reply strands
            // in the outbox and the loop advances time straight to the connect's
            // deadline, timing it out.
            self.collect_events();
            self.drain_outboxes();

            if steps >= max_steps {
                return steps;
            }
            steps += 1;

            let next_deliver = self.queue.peek().map(|Reverse(s)| s.time);
            let next_timeout = self.nodes.iter().filter_map(|n| n.dht.poll_timeout()).min();

            let next = match (next_deliver, next_timeout) {
                (Some(a), Some(b)) => a.min(b),
                (Some(a), None) => a,
                (None, Some(b)) => b,
                (None, None) => return steps, // quiescent
            };
            self.now = next;

            // Fire due timers first, then deliver due packets.
            for i in 0..self.nodes.len() {
                if let Some(t) = self.nodes[i].dht.poll_timeout() {
                    if t <= self.now {
                        let now = self.now;
                        self.nodes[i].dht.handle_timeout(now);
                    }
                }
            }
            while let Some(Reverse(slot)) = self.queue.peek() {
                if slot.time > self.now {
                    break;
                }
                let Reverse(slot) = self.queue.pop().unwrap();
                let Scheduled::Deliver { to, from, data } = slot.item;
                if self.disabled.contains(&to) {
                    continue; // recipient went offline after this was scheduled
                }
                let now = self.now;
                self.nodes[to].dht.handle_input(from, &data, now);
            }
        }
    }

    /// Brute-force the globally closest node id to `target`, excluding the id of
    /// node `exclude`. This is the oracle the iterative lookup is checked
    /// against: a correct Kademlia lookup must find exactly this node.
    pub fn brute_force_closest(&self, target: &NodeId, exclude: usize) -> NodeId {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != exclude)
            .map(|(_, n)| n.dht.id())
            .min_by_key(|id| id.distance(target))
            .expect("network has other nodes")
    }

    /// Convenience: the [`Contact`] for node `i`.
    pub fn contact(&self, i: usize) -> Contact {
        Contact::new(self.nodes[i].dht.id(), self.nodes[i].addr)
    }
}
