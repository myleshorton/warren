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
use crate::punch::{plan, Strategy};
use crate::routing::{Contact, RoutingTable, K};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

/// Peers to probe when sampling the local NAT.
pub const NAT_SAMPLE_COUNT: usize = 5;

/// How many recent connect initiators a coordinator remembers (bounded FIFO).
const MAX_SEEN_INITIATORS: usize = 1024;

/// Cap on pending incoming connects awaiting a [`Dht::accept_connect`], so a
/// flood of connect requests can't grow the target's state unboundedly. Beyond
/// this, new requests are dropped (the initiator simply times out).
const MAX_PENDING_INCOMING: usize = 256;

/// Absolute cap on distinct announce topics a node stores, bounding memory even
/// when the routing table is too small for [`Dht::responsible_for`] to bite.
const MAX_ANNOUNCE_TOPICS: usize = 65_536;

/// Concurrency parameter: how many lookup requests may be in flight at once.
pub const ALPHA: usize = 3;

/// How long (ms) to wait for a response before treating a request as failed.
pub const REQUEST_TIMEOUT_MS: u64 = 1_000;

/// Overall deadline (ms) for a connect — covering both discovery and the
/// coordinator-brokered signaling — after which it gives up.
pub const CONNECT_TIMEOUT_MS: u64 = 10_000;

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

/// How a coordinated connection was (or wasn't) established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// A reachable (Open) peer, or two predictable peers: a plain direct path.
    Direct,
    /// A hole was punched (one-sided-random birthday strategy).
    Punched,
    /// Both peers are symmetric, so no direct path can be punched. Reported as an
    /// outcome, but no data channel is established: relaying peer data is
    /// intentionally not built (it would load relays too heavily for a serverless
    /// model).
    Relayed,
    /// The target could not be found on the DHT (not announced).
    NotFound,
    /// The connect did not complete before its deadline — discovery or the
    /// coordinator-brokered signaling did not finish in time.
    TimedOut,
}

/// Something the DHT wants the caller to know about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A `find_node` lookup completed.
    QueryFinished {
        /// Which lookup.
        query: QueryId,
        /// The target that was searched for.
        target: NodeId,
        /// The closest live contacts found, nearest first.
        closest: Vec<Contact>,
    },
    /// A `lookup` completed, returning any announce records found for the topic.
    LookupFinished {
        /// The topic searched for.
        topic: NodeId,
        /// Peers that announced under the topic.
        peers: Vec<Contact>,
    },
    /// An `announce` completed (records were pushed to the closest nodes).
    AnnounceFinished {
        /// The topic announced under.
        topic: NodeId,
    },
    /// A `connect` completed, coordinated through the DHT.
    Connected {
        /// The peer connected to.
        target: NodeId,
        /// How the connection was established.
        outcome: ConnectOutcome,
        /// The target's data-socket candidate addresses to punch the channel to,
        /// in preference order, if the target accepted. Empty for
        /// `NotFound`/`TimedOut`, where there is no peer to punch to.
        peer_data_addrs: Vec<SocketAddr>,
        /// Our punch role toward the peer (from the two firewalls): dial, spray,
        /// or open birthday sockets. `None` when there is no peer to punch to
        /// (`NotFound`/`TimedOut`).
        strategy: Option<Strategy>,
    },
    /// A peer wants to connect to us (we are the target). The caller stands up a
    /// data socket, calls [`Dht::accept_connect`] with its candidate address(es)
    /// to complete the signaling, and runs the punch primitive `strategy`
    /// indicates — dial-accept, spray, or open birthday sockets — toward
    /// `initiator_data_addrs`. Ignore the event to decline.
    IncomingConnect {
        /// The peer initiating the connection.
        initiator: NodeId,
        /// The initiator's data-socket candidate addresses, in preference order —
        /// the hosts to accept a punch from / punch toward.
        initiator_data_addrs: Vec<SocketAddr>,
        /// Our punch role toward the initiator (from the two firewalls).
        strategy: Strategy,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueryKind {
    FindNode,
    Lookup,
    Announce,
    Connect,
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
    kind: QueryKind,
    contacts: Vec<QueryContact>,
    /// Nodes that returned an announce record for the target (potential
    /// coordinators for a connect).
    coordinators: Vec<Contact>,
    /// Announce records accumulated for the target during the search.
    peers: Vec<Contact>,
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

struct ConnectState {
    /// When this connect gives up if signaling hasn't completed.
    deadline: Millis,
    /// The coordinator we sent the request to; a reply is accepted only from it,
    /// so another host can't spoof a reply and force a wrong outcome.
    coordinator: Option<SocketAddr>,
    /// Our own data-socket candidate addresses, sent in the request so the target
    /// learns where to punch back.
    data_addrs: Vec<SocketAddr>,
}

/// The target side of an in-flight connect: a request arrived for us, and we
/// wait for the caller to supply our data-socket address via
/// [`Dht::accept_connect`] before replying to the initiator.
struct IncomingState {
    /// The coordinator that relayed the request; the reply goes back through it.
    coordinator: SocketAddr,
    /// The initiator's observed control address, echoed in the reply so the
    /// coordinator can match it to the initiator it remembered.
    initiator_addr: SocketAddr,
    /// When this pending incoming connect is discarded if never accepted.
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
    /// This node's own firewall type, shared with peers during connect signaling.
    local_firewall: Firewall,
    /// topic -> peers that have announced under it (records this node stores).
    announces: HashMap<NodeId, Vec<Contact>>,
    /// Targets we are mid-connect to -> the connect's state (deadline + the
    /// coordinator we're expecting the reply from).
    connecting: HashMap<NodeId, ConnectState>,
    /// Recently observed (target id, initiator address) connect pairs
    /// (coordinator side), bounded FIFO. We relay a reply only to an address
    /// that actually initiated a connect *to that target*, so a target can't
    /// redirect the relayed reply to an arbitrary victim (nor to an initiator of
    /// some other connect).
    seen_initiators: VecDeque<(NodeId, SocketAddr)>,
    /// Initiators (by id) whose connect request reached us as the target and
    /// awaits an [`Dht::accept_connect`] to complete the reply.
    pending_incoming: HashMap<NodeId, IncomingState>,
    outbox: VecDeque<Transmit>,
    events: VecDeque<Event>,
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
            local_firewall: Firewall::Open,
            announces: HashMap::new(),
            connecting: HashMap::new(),
            seen_initiators: VecDeque::new(),
            pending_incoming: HashMap::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
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

    /// Set this node's own firewall type (shared with peers during connect
    /// signaling). Normally derived from [`Dht::firewall`] after sampling.
    pub fn set_firewall(&mut self, fw: Firewall) {
        self.local_firewall = fw;
    }

    /// Begin a lookup for the nodes closest to our own id — the standard way to
    /// populate the routing table after learning a bootstrap peer.
    pub fn bootstrap(&mut self, now: Millis) -> QueryId {
        self.find_node(self.id, now)
    }

    /// Begin a lookup for the nodes closest to `target`.
    pub fn find_node(&mut self, target: NodeId, now: Millis) -> QueryId {
        self.start_query(target, QueryKind::FindNode, now)
    }

    /// Announce this node under `topic`: find the closest nodes and register
    /// ourselves with them, so peers looking up `topic` can discover us.
    pub fn announce(&mut self, topic: NodeId, now: Millis) -> QueryId {
        self.start_query(topic, QueryKind::Announce, now)
    }

    /// Look up peers that have announced under `topic`.
    pub fn lookup(&mut self, topic: NodeId, now: Millis) -> QueryId {
        self.start_query(topic, QueryKind::Lookup, now)
    }

    /// Connect to `target` by id: discover it on the DHT, then coordinate a hole
    /// punch through a node that holds its announce record. `data_addrs` are our
    /// own data-socket candidate addresses (preference order), sent to the target
    /// so it knows where to punch back. Completion is reported as an
    /// [`Event::Connected`] carrying the target's candidate addresses to punch to.
    pub fn connect(&mut self, target: NodeId, data_addrs: Vec<SocketAddr>, now: Millis) -> QueryId {
        self.connecting.insert(
            target,
            ConnectState {
                deadline: now + CONNECT_TIMEOUT_MS,
                coordinator: None,
                data_addrs,
            },
        );
        self.start_query(target, QueryKind::Connect, now)
    }

    /// Accept an incoming connect surfaced by [`Event::IncomingConnect`]: reply
    /// to `initiator` (through the coordinator that relayed the request) with our
    /// `data_addrs`, so it can punch a channel to us. A no-op if the request is no
    /// longer pending — already accepted, or past its deadline (the initiator has
    /// itself timed out, so a reply would be ignored).
    pub fn accept_connect(&mut self, initiator: NodeId, data_addrs: Vec<SocketAddr>, now: Millis) {
        if let Some(inc) = self.pending_incoming.remove(&initiator) {
            if inc.deadline <= now {
                return; // expired before we accepted; the initiator has given up
            }
            let rid = self.alloc_rid();
            let fw = self.signaling_firewall();
            self.send(
                inc.coordinator,
                rid,
                Message::Signal {
                    target: self.id,
                    initiator,
                    initiator_addr: inc.initiator_addr,
                    data_addrs,
                    nat: fw,
                    is_reply: true,
                },
            );
        }
    }

    fn start_query(&mut self, target: NodeId, kind: QueryKind, now: Millis) -> QueryId {
        let qid = self.next_qid;
        self.next_qid += 1;

        let mut query = Query {
            target,
            kind,
            contacts: Vec::new(),
            coordinators: Vec::new(),
            peers: Vec::new(),
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
        // Most packets are direct evidence the sender is reachable at `from`, so
        // fold it into the routing table. A `Reflect` is the exception: it comes
        // from a transient data socket (a reflexive probe), not a routable peer,
        // so inserting it would poison routing with an ephemeral address.
        if packet.sender != self.id && !matches!(&packet.msg, Message::Reflect) {
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
                // Include any announce records we hold for the queried target,
                // so a lookup discovers announcers as it converges.
                let peers = self.announces.get(&target).cloned().unwrap_or_default();
                self.send(from, packet.rid, Message::Nodes { contacts, peers });
            }
            Message::Nodes { contacts, peers } => {
                self.on_nodes_response(packet.rid, packet.sender, from, contacts, peers, now);
            }
            Message::Announce { topic } => {
                // Only store if we're plausibly responsible for the topic, so a
                // remote can't grow our store with announces for arbitrary keys.
                if self.responsible_for(&topic) {
                    self.store_announce(topic, Contact::new(packet.sender, from));
                }
            }
            Message::Reflect => {
                // Echo the observed source so a peer can learn its externally
                // mapped (post-NAT) address for the socket it probed from.
                self.send(from, packet.rid, Message::Reflected { observed: from });
            }
            Message::Reflected { .. } => {
                // A reply to our reflexive probe. The DHT core doesn't probe (the
                // driver does, on its data socket), so nothing to do here.
            }
            Message::Signal {
                target,
                initiator,
                initiator_addr,
                data_addrs,
                nat,
                is_reply,
            } => {
                self.on_signal(
                    from,
                    target,
                    initiator,
                    initiator_addr,
                    data_addrs,
                    nat,
                    is_reply,
                    now,
                );
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

        // Fail connects whose signaling never completed, so they can't hang.
        let stale: Vec<NodeId> = self
            .connecting
            .iter()
            .filter(|(_, cs)| cs.deadline <= now)
            .map(|(target, _)| *target)
            .collect();
        for target in stale {
            self.connecting.remove(&target);
            // Stop any still-running discovery for this target so it can't emit
            // a late Signal after we've already reported TimedOut.
            self.cancel_connect_queries(&target);
            self.events.push_back(Event::Connected {
                target,
                outcome: ConnectOutcome::TimedOut,
                peer_data_addrs: Vec::new(),
                strategy: None,
            });
        }

        // Discard incoming connect requests the caller never accepted, so an
        // unaccepted (or abandoned) request can't pin target-side state forever.
        self.pending_incoming.retain(|_, inc| inc.deadline > now);
    }

    /// The earliest pending deadline, if any request or connect is in flight.
    pub fn poll_timeout(&self) -> Option<Millis> {
        self.pending
            .values()
            .map(|p| p.deadline)
            .chain(self.nat_pending.values().copied())
            .chain(self.connecting.values().map(|cs| cs.deadline))
            .chain(self.pending_incoming.values().map(|inc| inc.deadline))
            .min()
    }

    /// Take the next packet to transmit, if any. O(1) via a front pop, so
    /// draining a full outbox is O(n) rather than O(n²).
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.outbox.pop_front()
    }

    /// Take the next event, if any. O(1) front pop (see [`Dht::poll_transmit`]).
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn send(&mut self, to: SocketAddr, rid: u64, msg: Message) {
        let data = Packet {
            sender: self.id,
            rid,
            msg,
        }
        .encode();
        self.outbox.push_back(Transmit { to, data });
    }

    fn on_nodes_response(
        &mut self,
        rid: u64,
        responder: NodeId,
        responder_addr: SocketAddr,
        contacts: Vec<Contact>,
        peers: Vec<Contact>,
        now: Millis,
    ) {
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
        // A responder is a candidate coordinator only if it holds the target's
        // own self-announce (a record whose id is the target); a non-empty peers
        // list under the topic that lacks it doesn't help a connect-by-id.
        if !peers.is_empty() {
            if peers.iter().any(|p| p.id == q.target) {
                let coord = Contact::new(responder, responder_addr);
                if !q.coordinators.iter().any(|c| c.id == coord.id) {
                    q.coordinators.push(coord);
                }
            }
            for peer in peers {
                // Last-reported address wins, so a re-announce (or a fresher
                // report from another coordinator) refreshes a known peer.
                if let Some(existing) = q.peers.iter_mut().find(|c| c.id == peer.id) {
                    existing.addr = peer.addr;
                } else {
                    q.peers.push(peer);
                }
            }
        }
        self.drive_query(p.query, now);
    }

    fn remember_initiator(&mut self, target: NodeId, addr: SocketAddr) {
        let key = (target, addr);
        if self.seen_initiators.contains(&key) {
            return;
        }
        if self.seen_initiators.len() >= MAX_SEEN_INITIATORS {
            self.seen_initiators.pop_front();
        }
        self.seen_initiators.push_back(key);
    }

    /// The firewall type to advertise in signaling: the sampler's classification
    /// once available, else the explicitly set value (default Open). This means a
    /// node that has sampled its NAT reports the right type without every caller
    /// having to remember to sync it.
    fn signaling_firewall(&self) -> Firewall {
        self.firewall().unwrap_or(self.local_firewall)
    }

    fn store_announce(&mut self, topic: NodeId, announcer: Contact) {
        // Don't create a new topic entry past the absolute cap (existing topics
        // still accept updates), so memory stays bounded even in small networks.
        if !self.announces.contains_key(&topic) && self.announces.len() >= MAX_ANNOUNCE_TOPICS {
            return;
        }
        let records = self.announces.entry(topic).or_default();
        if let Some(existing) = records.iter_mut().find(|c| c.id == announcer.id) {
            existing.addr = announcer.addr; // refresh the mapping
        } else if records.len() < K {
            records.push(announcer);
        }
    }

    /// Whether we are plausibly among the K closest nodes to `topic` — i.e.
    /// fewer than K known contacts are closer to it than we are. Announce
    /// records should live near their topic, so this bounds what we store.
    fn responsible_for(&self, topic: &NodeId) -> bool {
        let my_dist = self.id.distance(topic);
        let closer = self
            .table
            .closest(topic, K)
            .into_iter()
            .filter(|c| c.id.distance(topic) < my_dist)
            .count();
        closer < K
    }

    /// Drop any in-flight connect query (and its pending requests) for `target`,
    /// so a query that finishes after the connect already resolved can't send a
    /// stray `Signal`.
    fn cancel_connect_queries(&mut self, target: &NodeId) {
        let qids: Vec<QueryId> = self
            .queries
            .iter()
            .filter(|(_, q)| q.kind == QueryKind::Connect && q.target == *target)
            .map(|(id, _)| *id)
            .collect();
        for qid in &qids {
            self.queries.remove(qid);
        }
        self.pending.retain(|_, p| !qids.contains(&p.query));
    }

    fn alloc_rid(&mut self) -> u64 {
        let rid = self.next_rid;
        self.next_rid += 1;
        rid
    }

    #[allow(clippy::type_complexity)]
    fn drive_query(&mut self, qid: QueryId, now: Millis) {
        // Decide what to send, but collect first to avoid borrow conflicts.
        let mut to_send: Vec<(NodeId, SocketAddr)> = Vec::new();
        // On completion: (kind, target, closest, coordinators, peers).
        let mut done: Option<(QueryKind, NodeId, Vec<Contact>, Vec<Contact>, Vec<Contact>)> = None;

        if let Some(q) = self.queries.get_mut(&qid) {
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
                done = Some((
                    q.kind,
                    q.target,
                    closest,
                    q.coordinators.clone(),
                    q.peers.clone(),
                ));
            }
        }

        // The iterative search phase is FindNode for every query kind.
        let query_target = self.queries.get(&qid).map(|q| q.target);
        for (contact_id, addr) in to_send {
            let rid = self.alloc_rid();
            self.pending.insert(
                rid,
                Pending {
                    query: qid,
                    contact: contact_id,
                    deadline: now + REQUEST_TIMEOUT_MS,
                },
            );
            let target = query_target.expect("query exists");
            self.send(addr, rid, Message::FindNode { target });
        }

        if let Some((kind, target, closest, coordinators, peers)) = done {
            self.queries.remove(&qid);
            self.finish_query(qid, kind, target, closest, coordinators, peers);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_query(
        &mut self,
        qid: QueryId,
        kind: QueryKind,
        target: NodeId,
        closest: Vec<Contact>,
        coordinators: Vec<Contact>,
        peers: Vec<Contact>,
    ) {
        match kind {
            QueryKind::FindNode => {
                self.events.push_back(Event::QueryFinished {
                    query: qid,
                    target,
                    closest,
                });
            }
            QueryKind::Lookup => {
                self.events.push_back(Event::LookupFinished {
                    topic: target,
                    peers,
                });
            }
            QueryKind::Announce => {
                // Register ourselves with the closest nodes we found.
                for c in &closest {
                    let rid = self.alloc_rid();
                    self.send(c.addr, rid, Message::Announce { topic: target });
                }
                self.events
                    .push_back(Event::AnnounceFinished { topic: target });
            }
            QueryKind::Connect => match coordinators.first().copied() {
                Some(coord) => {
                    // Ask a coordinator (which holds the target's record) to relay
                    // our signal. It overwrites initiator_addr with the address it
                    // observes, so we needn't know our own external address.
                    // Record the coordinator so we accept the reply only from it.
                    let data_addrs = match self.connecting.get_mut(&target) {
                        Some(cs) => {
                            cs.coordinator = Some(coord.addr);
                            cs.data_addrs.clone()
                        }
                        None => return, // connect already resolved/expired
                    };
                    let rid = self.alloc_rid();
                    let fw = self.signaling_firewall();
                    self.send(
                        coord.addr,
                        rid,
                        Message::Signal {
                            target,
                            initiator: self.id,
                            initiator_addr: coord.addr, // placeholder; coordinator overwrites
                            data_addrs,
                            nat: fw,
                            is_reply: false,
                        },
                    );
                }
                None => {
                    self.connecting.remove(&target);
                    self.events.push_back(Event::Connected {
                        target,
                        outcome: ConnectOutcome::NotFound,
                        peer_data_addrs: Vec::new(),
                        strategy: None,
                    });
                }
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_signal(
        &mut self,
        from: SocketAddr,
        target: NodeId,
        initiator: NodeId,
        initiator_addr: SocketAddr,
        data_addrs: Vec<SocketAddr>,
        nat: Firewall,
        is_reply: bool,
        now: Millis,
    ) {
        if !is_reply {
            if target == self.id {
                // We are the target. We can't reply yet: the reply must carry our
                // data-socket address, which the caller supplies once it stands up
                // the socket. Record the request and surface it; `accept_connect`
                // sends the reply. `data_addrs` here are the initiator's data-socket
                // candidates — the hosts we'll accept a punch from.
                //
                // Emit `IncomingConnect` only the *first* time an initiator becomes
                // pending: each event makes the caller bind a socket and start a
                // punch, so re-emitting on duplicate (or replayed) requests would
                // drive unbounded churn.
                if let Some(inc) = self.pending_incoming.get_mut(&initiator) {
                    // Duplicate/replay: refresh only the deadline. Keep the first
                    // coordinator and control address, so a replay with the same
                    // (unauthenticated) initiator id can't redirect where
                    // `accept_connect` sends the reply.
                    inc.deadline = now + CONNECT_TIMEOUT_MS;
                } else if self.pending_incoming.len() < MAX_PENDING_INCOMING {
                    self.pending_incoming.insert(
                        initiator,
                        IncomingState {
                            coordinator: from,
                            initiator_addr,
                            deadline: now + CONNECT_TIMEOUT_MS,
                        },
                    );
                    // Our role toward the initiator, from our firewall and theirs.
                    let strategy = plan(self.signaling_firewall(), nat);
                    self.events.push_back(Event::IncomingConnect {
                        initiator,
                        initiator_data_addrs: data_addrs,
                        strategy,
                    });
                }
            } else if let Some(target_addr) = self
                .announces
                .get(&target)
                .and_then(|r| r.iter().find(|c| c.id == target))
                .map(|c| c.addr)
            {
                // We are a coordinator: forward to the target's own record (the
                // announcer whose id is the target), over the mapping it opened
                // by announcing to us, filling in the observed initiator addr. The
                // initiator's `data_addrs` pass through unchanged — we can't
                // observe its data socket, only its control source `from`.
                // Remember the initiator so we'll only relay the reply back to an
                // address that actually initiated.
                self.remember_initiator(target, from);
                let rid = self.alloc_rid();
                self.send(
                    target_addr,
                    rid,
                    Message::Signal {
                        target,
                        initiator,
                        initiator_addr: from,
                        data_addrs,
                        nat,
                        is_reply: false,
                    },
                );
            }
        } else if initiator == self.id {
            // We are the initiator: the reply carries the target's firewall and
            // data address — but accept it only from the coordinator we actually
            // sent the request to, so another host can't spoof a reply and force a
            // wrong outcome (or feed us a bogus punch target).
            let from_coordinator = self
                .connecting
                .get(&target)
                .is_some_and(|cs| cs.coordinator == Some(from));
            if from_coordinator {
                self.connecting.remove(&target);
                let strategy = plan(self.signaling_firewall(), nat);
                self.events.push_back(Event::Connected {
                    target,
                    outcome: outcome_for(strategy),
                    peer_data_addrs: data_addrs,
                    strategy: Some(strategy),
                });
            }
        } else if self.seen_initiators.contains(&(target, initiator_addr))
            && self
                .announces
                .get(&target)
                .is_some_and(|recs| recs.iter().any(|c| c.id == target && c.addr == from))
        {
            // We are the coordinator relaying the reply — but only to an address
            // that actually initiated (so the target can't redirect it to a
            // victim), and only if the reply truly came from the target's own
            // record (id == target, at that address). The target's `data_addrs`
            // pass through unchanged.
            // Otherwise an arbitrary announcer under the same topic could spoof a
            // reply to use us as a reflector or feed the initiator a bogus
            // firewall type. (Full authentication — a Noise handshake and
            // capability tokens, as in HyperDHT — is future work; it would also
            // stop a peer from announcing under another peer's id at all.)
            let rid = self.alloc_rid();
            self.send(
                initiator_addr,
                rid,
                Message::Signal {
                    target,
                    initiator,
                    initiator_addr,
                    data_addrs,
                    nat,
                    is_reply: true,
                },
            );
        }
    }
}

/// Map a punch [`Strategy`] to the user-facing connection outcome. The strategy
/// comes from [`plan`]; the punch's success probability for the one-sided-random
/// cases is verified separately in `punch`.
fn outcome_for(strategy: Strategy) -> ConnectOutcome {
    match strategy {
        Strategy::Direct => ConnectOutcome::Direct,
        Strategy::SprayRandomPorts | Strategy::OpenBirthdaySockets => ConnectOutcome::Punched,
        Strategy::Relay => ConnectOutcome::Relayed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::Packet;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn id(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
    }

    fn signal_request(initiator: NodeId, target: NodeId, data_addr: SocketAddr) -> Vec<u8> {
        Packet {
            sender: id(9),
            rid: 1,
            msg: Message::Signal {
                target,
                initiator,
                initiator_addr: addr("10.0.0.2:100"),
                data_addrs: vec![data_addr],
                nat: Firewall::Consistent,
                is_reply: false,
            },
        }
        .encode()
    }

    /// A connect request replayed for the same initiator must surface
    /// `IncomingConnect` only once — each event drives the caller to bind a
    /// socket and start a punch, so re-emitting on duplicates (which an
    /// unauthenticated peer can replay) would be an amplification vector — and a
    /// replay via a *different* coordinator must not redirect where the reply is
    /// later sent.
    #[test]
    fn duplicate_incoming_requests_emit_once_and_dont_redirect() {
        let me = id(1);
        let initiator = id(2);
        let mut dht = Dht::new(me);
        let coord_a = addr("10.0.0.9:900");
        let coord_b = addr("10.0.0.8:800"); // a replay's (spoofed) coordinator

        let request = signal_request(initiator, me, addr("10.0.0.2:200"));
        dht.handle_input(coord_a, &request, 0);
        dht.handle_input(coord_b, &request, 0); // replay via a different coordinator

        let incoming = std::iter::from_fn(|| dht.poll_event())
            .filter(|e| matches!(e, Event::IncomingConnect { .. }))
            .count();
        assert_eq!(
            incoming, 1,
            "duplicate requests must emit exactly one event"
        );

        // Accepting sends the reply back through the *first* coordinator, never
        // the replay's — the replay can't redirect it.
        dht.accept_connect(initiator, vec![addr("10.0.0.1:50")], 1);
        let reply_dests: Vec<SocketAddr> = std::iter::from_fn(|| dht.poll_transmit())
            .map(|t| t.to)
            .collect();
        assert!(
            reply_dests.contains(&coord_a),
            "reply must go to the first coordinator, got {reply_dests:?}"
        );
        assert!(
            !reply_dests.contains(&coord_b),
            "a replay must not redirect the reply to its coordinator"
        );
    }

    /// A `Reflect` is echoed to its source but, unlike a `Ping`, does not add the
    /// (transient data-socket) sender to routing — otherwise a reflexive probe
    /// would poison the table with an ephemeral address.
    #[test]
    fn reflect_is_echoed_without_poisoning_routing() {
        let mut dht = Dht::new(id(1));
        // Stands in for a NAT-mapped data-socket source.
        let prober = addr("203.0.113.7:51000");

        let reflect = Packet {
            sender: id(2),
            rid: 5,
            msg: Message::Reflect,
        }
        .encode();
        dht.handle_input(prober, &reflect, 0);

        let replies: Vec<_> = std::iter::from_fn(|| dht.poll_transmit()).collect();
        assert_eq!(replies.len(), 1, "a Reflect must be answered once");
        assert_eq!(replies[0].to, prober);
        assert_eq!(
            Packet::decode(&replies[0].data).unwrap().msg,
            Message::Reflected { observed: prober },
            "Reflected must echo the observed source"
        );
        assert_eq!(
            dht.routing_len(),
            0,
            "a Reflect must not add the transient prober to routing"
        );

        // Contrast: a Ping from the same peer *is* routing evidence.
        let ping = Packet {
            sender: id(2),
            rid: 6,
            msg: Message::Ping,
        }
        .encode();
        dht.handle_input(prober, &ping, 0);
        assert_eq!(dht.routing_len(), 1, "a Ping is routing evidence");
    }
}
