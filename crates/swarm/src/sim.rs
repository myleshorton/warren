//! Deterministic in-memory network simulator for the [`Dht`] core.
//!
//! Because [`Dht`] is sans-IO, we can run many nodes against a virtual clock
//! with a fully controlled network and get **repeatable, flake-free** results:
//! packet delivery is scheduled in a priority queue keyed by `(time, seq)`, so
//! ordering is deterministic, and all randomness comes from a seeded PRNG. This
//! is the primary way DHT behavior is verified before any real socket exists.

use crate::dht::{Dht, Event, Millis, QueryId};
use crate::id::{NodeId, ID_LEN};
use crate::routing::Contact;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
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
        let mut b = [0u8; ID_LEN];
        for chunk in b.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        NodeId::from_bytes(b)
    }

    /// A float in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct Node {
    dht: Dht,
    addr: SocketAddr,
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
    queue: BinaryHeap<Reverse<Slot>>,
    seq: u64,
    latency_ms: Millis,
    loss: f64,
    rng: Rng,
    events: Vec<(usize, Event)>,
}

impl Sim {
    /// Create a simulator with a fixed one-way latency and a seed.
    pub fn new(latency_ms: Millis, seed: u64) -> Self {
        Self {
            now: 0,
            nodes: Vec::new(),
            by_addr: HashMap::new(),
            queue: BinaryHeap::new(),
            seq: 0,
            latency_ms,
            loss: 0.0,
            rng: Rng::new(seed),
            events: Vec::new(),
        }
    }

    /// Set the packet loss probability in `[0, 1)`.
    pub fn set_loss(&mut self, loss: f64) {
        self.loss = loss;
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
        });
        self.by_addr.insert(addr, index);
        (index, addr)
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
            let from = self.nodes[i].addr;
            while let Some(t) = self.nodes[i].dht.poll_transmit() {
                let Some(&to) = self.by_addr.get(&t.to) else {
                    continue; // unknown destination: dropped, as on a real net
                };
                if self.loss > 0.0 && self.rng.unit() < self.loss {
                    continue; // simulated packet loss
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
            self.drain_outboxes();
            self.collect_events();

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
