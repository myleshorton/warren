//! The DHT core: a sans-IO Kademlia state machine.
//!
//! This type performs **no I/O and reads no clock**. It consumes inputs
//! (incoming packets, timer fires) and produces outputs (packets to transmit,
//! events, a next-deadline), all driven by a caller who supplies the current
//! time as a millisecond count. That separation is what lets the exact same
//! logic run under a deterministic simulator (see [`crate::sim`]) and, later,
//! over real UDP sockets — and it is why the behavior is flake-free to test.
//!
//! The one algorithm here is the Kademlia iterative node lookup: to find the
//! nodes closest to a target, repeatedly query the closest not-yet-queried
//! nodes we know (up to [`ALPHA`] in flight), folding each reply's contacts
//! back into a shortlist, until the `K` closest have all been queried.

use crate::id::NodeId;
use crate::msg::{Message, Packet};
use crate::nat::{Firewall, NatSampler};
use crate::routing::{Contact, RoutingTable, K};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Peers to probe when sampling the local NAT.
pub const NAT_SAMPLE_COUNT: usize = 5;

/// Concurrency parameter: how many lookup requests may be in flight at once.
pub const ALPHA: usize = 3;

/// How long (ms) to wait for a response before treating a request as failed.
pub const REQUEST_TIMEOUT_MS: u64 = 1_000;

/// Milliseconds since an arbitrary epoch chosen by the caller.
pub type Millis = u64;

/// Identifies a lookup started via [`Dht::find_node`].
pub type QueryId = u64;

/// A packet the caller must deliver to `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    /// Destination address.
    pub to: SocketAddr,
    /// Encoded packet bytes.
    pub data: Vec<u8>,
}

/// Something the DHT wants the caller to know about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A lookup completed.
    QueryFinished {
        /// Which lookup.
        query: QueryId,
        /// The target that was searched for.
        target: NodeId,
        /// The closest live contacts found, nearest first.
        closest: Vec<Contact>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Fresh,
    InFlight,
    Done,
    Failed,
}

struct QueryContact {
    contact: Contact,
    status: Status,
}

struct Query {
    target: NodeId,
    contacts: Vec<QueryContact>,
}

impl Query {
    fn find(&mut self, id: &NodeId) -> Option<&mut QueryContact> {
        self.contacts.iter_mut().find(|c| c.contact.id == *id)
    }

    fn add_if_new(&mut self, contact: Contact) {
        if !self.contacts.iter().any(|c| c.contact.id == contact.id) {
            self.contacts.push(QueryContact {
                contact,
                status: Status::Fresh,
            });
        }
    }

    fn in_flight(&self) -> usize {
        self.contacts
            .iter()
            .filter(|c| c.status == Status::InFlight)
            .count()
    }

    /// Indices of contacts sorted nearest-first to the target.
    fn sorted_indices(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.contacts.len()).collect();
        idx.sort_by_key(|&i| self.contacts[i].contact.id.distance(&self.target));
        idx
    }
}

struct Pending {
    query: QueryId,
    contact: NodeId,
    deadline: Millis,
}

/// A Kademlia DHT node.
pub struct Dht {
    id: NodeId,
    table: RoutingTable,
    queries: HashMap<QueryId, Query>,
    pending: HashMap<u64, Pending>,
    nat: NatSampler,
    nat_pending: HashMap<u64, Millis>,
    self_reachable: bool,
    outbox: Vec<Transmit>,
    events: Vec<Event>,
    next_rid: u64,
    next_qid: QueryId,
}

impl Dht {
    /// Create a node with the given id.
    pub fn new(id: NodeId) -> Self {
        Self {
            id,
            table: RoutingTable::new(id),
            queries: HashMap::new(),
            pending: HashMap::new(),
            nat: NatSampler::new(),
            nat_pending: HashMap::new(),
            self_reachable: false,
            outbox: Vec::new(),
            events: Vec::new(),
            next_rid: 1,
            next_qid: 1,
        }
    }

    /// This node's id.
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// Number of contacts in the routing table.
    pub fn routing_len(&self) -> usize {
        self.table.len()
    }

    /// The `n` contacts closest to `target` currently in the routing table.
    pub fn closest(&self, target: &NodeId, n: usize) -> Vec<Contact> {
        self.table.closest(target, n)
    }

    /// Seed a bootstrap contact into the routing table.
    pub fn add_contact(&mut self, contact: Contact) {
        self.table.insert(contact);
    }

    /// Probe up to `count` known peers to learn our externally-observed address.
    ///
    /// Each peer replies with the source address it saw; those observations feed
    /// the [`NatSampler`], which classifies our firewall once enough arrive. This
    /// is the outbound half of NAT detection; reachability (Open vs Consistent)
    /// comes from a separate inbound probe fed via [`Dht::note_reachable`].
    pub fn sample_nat(&mut self, now: Millis, count: usize) {
        let peers: Vec<SocketAddr> = self
            .table
            .closest(&self.id, count)
            .into_iter()
            .map(|c| c.addr)
            .collect();
        for addr in peers {
            let rid = self.next_rid;
            self.next_rid += 1;
            self.nat_pending.insert(rid, now + REQUEST_TIMEOUT_MS);
            self.send(addr, rid, Message::Ping);
        }
    }

    /// Record whether an inbound reachability probe succeeded (drives the
    /// Open-vs-Consistent distinction). The probe that produces this signal
    /// lands with the NAT-translating packet simulator.
    pub fn note_reachable(&mut self, reachable: bool) {
        self.self_reachable = reachable;
    }

    /// The current NAT classification, or `None` until enough samples arrive.
    pub fn firewall(&self) -> Option<Firewall> {
        self.nat.classify(self.self_reachable)
    }

    /// Number of NAT observations collected so far.
    pub fn nat_samples(&self) -> usize {
        self.nat.len()
    }

    /// Begin a lookup for the nodes closest to our own id — the standard way to
    /// populate the routing table after learning a bootstrap peer.
    pub fn bootstrap(&mut self, now: Millis) -> QueryId {
        self.find_node(self.id, now)
    }

    /// Begin a lookup for the nodes closest to `target`.
    pub fn find_node(&mut self, target: NodeId, now: Millis) -> QueryId {
        let qid = self.next_qid;
        self.next_qid += 1;

        let mut query = Query {
            target,
            contacts: Vec::new(),
        };
        for c in self.table.closest(&target, K) {
            query.add_if_new(c);
        }
        self.queries.insert(qid, query);
        self.drive_query(qid, now);
        qid
    }

    /// Handle a packet received from `from`.
    pub fn handle_input(&mut self, from: SocketAddr, data: &[u8], now: Millis) {
        let Ok(packet) = Packet::decode(data) else {
            return;
        };
        // Every packet is direct evidence the sender is reachable at `from`.
        if packet.sender != self.id {
            self.table.insert(Contact::new(packet.sender, from));
        }

        match packet.msg {
            Message::Ping => {
                // Echo back the source address we saw, so the sender can learn
                // how the network observes it.
                self.send(from, packet.rid, Message::Pong { observed: from });
            }
            Message::Pong { observed } => {
                if self.nat_pending.remove(&packet.rid).is_some() {
                    self.nat.add(observed);
                }
            }
            Message::FindNode { target } => {
                let contacts = self.table.closest(&target, K);
                self.send(from, packet.rid, Message::Nodes { contacts });
            }
            Message::Nodes { contacts } => {
                self.on_nodes_response(packet.rid, contacts, now);
            }
        }
    }

    /// Fire any timers whose deadline has passed.
    pub fn handle_timeout(&mut self, now: Millis) {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(rid, _)| *rid)
            .collect();

        for rid in expired {
            if let Some(p) = self.pending.remove(&rid) {
                if let Some(q) = self.queries.get_mut(&p.query) {
                    if let Some(c) = q.find(&p.contact) {
                        c.status = Status::Failed;
                    }
                }
                self.drive_query(p.query, now);
            }
        }

        // Expire NAT probes; a lost Pong simply yields one fewer sample.
        self.nat_pending.retain(|_, deadline| *deadline > now);
    }

    /// The earliest pending deadline, if any request is in flight.
    pub fn poll_timeout(&self) -> Option<Millis> {
        self.pending
            .values()
            .map(|p| p.deadline)
            .chain(self.nat_pending.values().copied())
            .min()
    }

    /// Take the next packet to transmit, if any.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        if self.outbox.is_empty() {
            None
        } else {
            Some(self.outbox.remove(0))
        }
    }

    /// Take the next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }

    fn send(&mut self, to: SocketAddr, rid: u64, msg: Message) {
        let data = Packet {
            sender: self.id,
            rid,
            msg,
        }
        .encode();
        self.outbox.push(Transmit { to, data });
    }

    fn on_nodes_response(&mut self, rid: u64, contacts: Vec<Contact>, now: Millis) {
        let Some(p) = self.pending.remove(&rid) else {
            return;
        };
        let Some(q) = self.queries.get_mut(&p.query) else {
            return;
        };
        if let Some(c) = q.find(&p.contact) {
            c.status = Status::Done;
        }
        for c in contacts {
            if c.id != self.id {
                q.add_if_new(c);
            }
        }
        self.drive_query(p.query, now);
    }

    fn drive_query(&mut self, qid: QueryId, now: Millis) {
        // Decide what to send, but collect first to avoid borrow conflicts.
        let mut to_send: Vec<(NodeId, SocketAddr)> = Vec::new();
        let mut finished: Option<Vec<Contact>> = None;
        let mut target = None;

        if let Some(q) = self.queries.get_mut(&qid) {
            target = Some(q.target);
            let order = q.sorted_indices();
            let topk: Vec<usize> = order.iter().take(K).copied().collect();

            let mut in_flight = q.in_flight();
            for &i in &topk {
                if in_flight >= ALPHA {
                    break;
                }
                if q.contacts[i].status == Status::Fresh {
                    q.contacts[i].status = Status::InFlight;
                    to_send.push((q.contacts[i].contact.id, q.contacts[i].contact.addr));
                    in_flight += 1;
                }
            }

            let topk_has_fresh = topk.iter().any(|&i| q.contacts[i].status == Status::Fresh);
            if to_send.is_empty() && in_flight == 0 && !topk_has_fresh {
                let closest = topk
                    .iter()
                    .filter(|&&i| q.contacts[i].status == Status::Done)
                    .map(|&i| q.contacts[i].contact)
                    .collect();
                finished = Some(closest);
            }
        }

        for (contact_id, addr) in to_send {
            let rid = self.next_rid;
            self.next_rid += 1;
            self.pending.insert(
                rid,
                Pending {
                    query: qid,
                    contact: contact_id,
                    deadline: now + REQUEST_TIMEOUT_MS,
                },
            );
            let target = target.expect("query exists");
            self.send(addr, rid, Message::FindNode { target });
        }

        if let Some(closest) = finished {
            self.queries.remove(&qid);
            self.events.push(Event::QueryFinished {
                query: qid,
                target: target.expect("query existed"),
                closest,
            });
        }
    }
}
