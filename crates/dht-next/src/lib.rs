//! Experimental replacement DHT: discovery, values, and DHT-mediated signaling.
//!
//! The caller supplies monotonic milliseconds, Unix seconds, and fresh secret entropy,
//! delivers datagrams,
//! and executes returned actions. No sockets, clocks, tasks, or application data
//! relays live here by default. The opt-in `diagnostics` feature adds profiling clocks. `driver::next::Node` provides the explicit UDP adapter.
#[cfg(feature = "diagnostics")]
pub mod diagnostics;
pub mod protocol;
mod publication;
mod routing;
mod session;
mod signaling;
#[cfg(feature = "test-support")]
pub mod testing;
pub use publication::MAX_PUBLICATIONS;
pub use routing::{distinct_networks, select_diverse_contact, RoutingPolicy};
pub use signaling::ReceivedSignal;
mod value;
pub use value::{
    MutableValue, Value, ValueLookupResult, MAX_SALT, MAX_VALUE, MAX_VALUES, VALUE_TTL_SECS,
};
mod timing;
use timing::Rtt;
pub use timing::Time;

use crypto::Keypair;
use protocol::{encode_addr, Body, Packet};
pub use protocol::{node_id, Record, Signal};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
pub use swarm::{Contact, NodeId};
use wire::Encoder;

pub const MAX_PENDING: usize = 128;
pub const MAX_QUERIES: usize = 16;
pub const MAX_CANDIDATES: usize = 128;
pub const MAX_REGISTRATIONS: usize = 256;
pub const MAX_SESSIONS: usize = 128;
pub const MAX_COORDINATORS: usize = 3;
pub const MAX_REPLAYS: usize = 2048;
const MAX_ROUTING: usize = 5120;
const COOKIE_MS: u64 = 30_000;
const QUERY_MS: u64 = 40_000;
const MAX_PEERS: usize = 5120;
const MAX_RETRIES: u8 = 4;
const MAX_FLIGHT: usize = 6;
const ALPHA: usize = 3;
const K: usize = 20;
const MAX_CANDIDATES_PER_ORIGIN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Send { to: SocketAddr, bytes: Vec<u8> },
    Event(Box<Event>),
}

impl Action {
    fn event(event: Event) -> Self {
        Self::Event(Box::new(event))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    NetworkChanged(u64),
    Ready(Contact),
    ObservedAddress {
        request: [u8; 32],
        reflector: Contact,
        address: SocketAddr,
    },
    Registered(Record),
    Providers {
        query: u64,
        records: Vec<Record>,
    },
    ProviderPage {
        request: [u8; 32],
        coordinator: Contact,
        topic: NodeId,
        records: Vec<Record>,
        next: Option<NodeId>,
    },
    ValueStored {
        request: [u8; 32],
        key: NodeId,
        stored: bool,
    },
    Value {
        request: [u8; 32],
        coordinator: Contact,
        key: NodeId,
        value: Option<Value>,
    },
    ValueLookupDone {
        query: u64,
        key: NodeId,
        result: ValueLookupResult,
    },
    LookupDone {
        query: u64,
        closest: Vec<Contact>,
        timed_out: bool,
    },
    Incoming {
        coordinator: Contact,
        signal: ReceivedSignal,
    },
    Answered(ReceivedSignal),
    SignalTimedOut([u8; 32]),
    RpcTimedOut([u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Capacity,
    Invalid,
    UnknownSession,
}

struct Pending {
    contact: Contact,
    packet: Packet,
    handshake: Option<snow::HandshakeState>,
    deadline: u64,
    retry_at: u64,
    query: Option<u64>,
    challenged: u8,
    sent_at: u64,
    hedge_at: u64,
    hedged: bool,
    retry_delay: u64,
    retries: u8,
    ambiguous: bool,
}

struct Peer {
    epoch: u64,
    cookie: [u8; 32],
    token_until: u64,
    expires: u64,
    rtt: Rtt,
}

struct Replay {
    expires: u64,
    from: SocketAddr,
    response: Vec<u8>,
    packet: Option<Packet>,
}

struct Route {
    contact: Contact,
    expires: u64,
}
struct Registration {
    record: Record,
    endpoint: Contact,
}
struct ManagedRegistration {
    publication: Option<NodeId>,
    coordinator: Contact,
    pending: Option<[u8; 32]>,
    next_at: u64,
    failures: u8,
    lease_expires: Option<u64>,
}

struct Exchange {
    initiator: Contact,
    target: Contact,
    expires: u64,
    answered: bool,
}
struct Incoming {
    handshake: Option<snow::HandshakeState>,
    sealed_answer: Option<(Signal, [u8; 32])>,
    coordinators: Vec<Contact>,
    offer: Signal,
    answered: bool,
}
struct Outgoing {
    alternates: Vec<Record>,
    coordinators: Vec<Contact>,
    offer: Option<Signal>,
    failover_at: u64,
    handshake: Option<snow::HandshakeState>,
    deadline: u64,
    target: NodeId,
    expires: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Fresh,
    Flight,
    Done,
    Failed,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum QueryOwner {
    Application,
    Value,
    Publication(NodeId),
    Routing,
}

#[derive(Clone, Copy)]
struct Candidate {
    contact: Contact,
    status: Status,
    referrer: Option<NodeId>,
}

struct Query {
    owner: QueryOwner,
    target: NodeId,
    deadline: u64,
    contacts: BTreeMap<NodeId, Candidate>,
    records: BTreeSet<(NodeId, NodeId)>,
    protected_seeds: BTreeSet<NodeId>,
    value: Option<ValueLookupResult>,
}

impl Query {
    fn add_candidates(
        &mut self,
        local: NodeId,
        policy: RoutingPolicy,
        referrer: Option<NodeId>,
        candidates: impl IntoIterator<Item = Contact>,
    ) {
        if referrer.is_some_and(|id| {
            !self
                .contacts
                .get(&id)
                .is_some_and(|c| c.status == Status::Done)
        }) {
            return;
        }
        let mut candidates: Vec<_> = candidates
            .into_iter()
            .filter(|c| !self.contacts.contains_key(&c.id))
            .map(|contact| Candidate {
                contact,
                status: Status::Fresh,
                referrer,
            })
            .collect();
        if policy == RoutingPolicy::Diverse {
            candidates.extend(
                self.contacts
                    .values()
                    .filter(|c| {
                        c.status == Status::Fresh && !self.protected_seeds.contains(&c.contact.id)
                    })
                    .copied(),
            );
            // Preserve caller-supplied paths before ranking attacker-supplied
            // referrals. Completed ancestors and active/failure budgets stay pinned.
            self.contacts
                .retain(|id, c| c.status != Status::Fresh || self.protected_seeds.contains(id));
        }
        candidates.sort_by_key(|c| c.contact.id.distance(&self.target));
        for candidate in candidates {
            let contact = candidate.contact;
            if self.contacts.len() >= MAX_CANDIDATES {
                break;
            }
            if contact.id == local
                || !usable(contact.addr)
                || self.contacts.contains_key(&contact.id)
                || !policy.allows_candidate(contact, self.contacts.values().map(|c| c.contact))
            {
                continue;
            }
            if policy == RoutingPolicy::Diverse {
                let origin = candidate
                    .referrer
                    .map_or(contact.id, |parent| self.origin(parent));
                if self
                    .contacts
                    .keys()
                    .filter(|id| self.origin(**id) == origin)
                    .count()
                    >= MAX_CANDIDATES_PER_ORIGIN
                {
                    continue;
                }
            }
            self.contacts.insert(contact.id, candidate);
        }
    }
    fn origin(&self, mut id: NodeId) -> NodeId {
        // Parents are already admitted and never reassigned, so the chain is acyclic.
        while let Some(parent) = self.contacts[&id].referrer {
            id = parent;
        }
        id
    }

    fn select_candidates(
        &self,
        mut fresh: Vec<Contact>,
        slots: usize,
        policy: RoutingPolicy,
    ) -> Vec<Contact> {
        if policy == RoutingPolicy::Unrestricted {
            return fresh.into_iter().take(slots).collect();
        }
        let mut active = BTreeMap::<NodeId, usize>::new();
        for c in self
            .contacts
            .values()
            .filter(|c| c.status == Status::Flight)
        {
            *active.entry(self.origin(c.contact.id)).or_default() += 1;
        }
        let mut selected = Vec::new();
        while selected.len() < slots && !fresh.is_empty() {
            let index = fresh
                .iter()
                .enumerate()
                .min_by_key(|(_, c)| {
                    (
                        active.get(&self.origin(c.id)).copied().unwrap_or(0),
                        c.id.distance(&self.target),
                    )
                })
                .unwrap()
                .0;
            let contact = fresh.remove(index);
            *active.entry(self.origin(contact.id)).or_default() += 1;
            selected.push(contact);
        }
        selected
    }
}

/// All long-lived collections have hard ceilings. Calls return their output
/// directly, so an undrained output queue cannot accumulate inside the core.
pub struct Dht {
    identity: Keypair,
    signaling_key: snow::Keypair,
    signaling_key_started: Option<u64>,
    retired_signaling_keys: Vec<signaling::RetiredKey>,
    secret: [u8; 32],
    server: bool,
    serial: u64,
    query_serial: u64,
    network_generation: u64,
    routes: BTreeMap<NodeId, Route>,
    routing: Option<routing::Maintenance>,
    routing_policy: RoutingPolicy,
    peers: BTreeMap<(NodeId, SocketAddr), Peer>,
    transport: session::Sessions,
    pending: BTreeMap<[u8; 32], Pending>,
    replay: BTreeMap<(NodeId, [u8; 32]), Replay>,
    registrations: BTreeMap<(NodeId, NodeId), Registration>,
    authorizations: BTreeMap<(NodeId, NodeId), Registration>,
    managed: BTreeMap<(NodeId, NodeId), ManagedRegistration>,
    exchanges: BTreeMap<[u8; 32], Exchange>,
    incoming: BTreeMap<[u8; 32], Incoming>,
    outgoing: BTreeMap<[u8; 32], Outgoing>,
    queries: BTreeMap<u64, Query>,
    publications: BTreeMap<NodeId, publication::Publication>,
    values: BTreeMap<NodeId, value::Stored>,
    #[cfg(feature = "test-support")]
    test_storage: testing::StorageFaults,
    #[cfg(feature = "test-support")]
    test_has_written: bool,
    budget_second: u64,
    budget_used: usize,
    budget_prefixes: BTreeMap<routing::Prefix, usize>,
}

impl Drop for Dht {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
        self.signaling_key.private.zeroize();
    }
}

impl Dht {
    /// `secret` must be fresh CSPRNG output on every process start, never reused
    /// with this identity. Tests can supply deterministic seeds. `server` is an
    /// operator/reachability-policy decision, not something authentication proves.
    pub fn new(identity: Keypair, secret: [u8; 32], server: bool) -> Self {
        Self::with_routing_policy(identity, secret, server, RoutingPolicy::default())
    }

    /// Choose routing and lookup policy at construction. `Unrestricted` is intended
    /// for controlled private networks and historical benchmark configurations.
    /// The entropy and reachability requirements of `new` still apply.
    pub fn with_routing_policy(
        identity: Keypair,
        secret: [u8; 32],
        server: bool,
        routing_policy: RoutingPolicy,
    ) -> Self {
        Self {
            identity,
            signaling_key: signaling::keypair(),
            signaling_key_started: None,
            retired_signaling_keys: Vec::new(),
            secret,
            server,
            serial: 0,
            query_serial: 0,
            network_generation: 0,
            routes: BTreeMap::new(),
            routing: None,
            routing_policy,
            peers: BTreeMap::new(),
            transport: session::Sessions::new(),
            pending: BTreeMap::new(),
            replay: BTreeMap::new(),
            registrations: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            managed: BTreeMap::new(),
            exchanges: BTreeMap::new(),
            incoming: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            queries: BTreeMap::new(),
            publications: BTreeMap::new(),
            values: BTreeMap::new(),
            #[cfg(feature = "test-support")]
            test_storage: testing::StorageFaults::default(),
            #[cfg(feature = "test-support")]
            test_has_written: false,
            budget_second: 0,
            budget_used: 0,
            budget_prefixes: BTreeMap::new(),
        }
    }

    /// Invalidate address-bound state after a local network change. Identity,
    /// signaling keys, hosted values and publication intentions survive.
    /// `secret` must be fresh entropy, invalidating old endpoint cookies.
    pub fn network_changed(
        &mut self,
        secret: [u8; 32],
        seeds: &[Contact],
        now: Time,
    ) -> Result<Vec<Action>, Error> {
        if seeds.len() > 8 || seeds.iter().any(|c| c.id == self.id() || !usable(c.addr)) {
            return Err(Error::Invalid);
        }
        let hints = if seeds.is_empty() {
            self.bootstrap_contacts(now)
        } else {
            seeds.to_vec()
        };
        use zeroize::Zeroize;
        self.secret.zeroize();
        self.secret = secret;
        self.routes.clear();
        self.routing = None;
        self.peers.clear();
        self.transport = session::Sessions::new();
        self.pending.clear();
        self.queries.clear();
        self.managed.clear();
        self.exchanges.clear();
        self.incoming.clear();
        self.outgoing.clear();
        self.network_generation = self
            .network_generation
            .checked_add(1)
            .expect("network generation exhausted");
        let mut actions = vec![Action::event(Event::NetworkChanged(
            self.network_generation,
        ))];
        actions.extend(self.restart_publications(seeds, now));
        actions.extend(self.maintain_routing(now));
        if !hints.is_empty() {
            if let Ok((_, sent)) = self.bootstrap(&hints, now) {
                actions.extend(sent);
            }
        }
        Ok(actions)
    }
    pub fn id(&self) -> NodeId {
        node_id(self.identity.public())
    }
    pub fn routing_len(&self) -> usize {
        self.routes.len()
    }
    /// Bounded live contact hints for restart. Restoring these through bootstrap
    /// revalidates identity and reachability; this exports no session secrets.
    pub fn bootstrap_contacts(&self, now: Time) -> Vec<Contact> {
        let mut contacts: Vec<_> = self
            .routes
            .values()
            .filter(|route| route.expires > now.monotonic_ms)
            .map(|route| route.contact)
            .collect();
        // Round-robin across XOR buckets before taking the bounded seed set.
        contacts
            .sort_by_key(|contact| (self.id().distance(&contact.id).leading_zeros(), contact.id));
        let mut buckets: BTreeMap<u32, Vec<Contact>> = BTreeMap::new();
        for contact in contacts {
            buckets
                .entry(self.id().distance(&contact.id).leading_zeros())
                .or_default()
                .push(contact);
        }
        let mut result = Vec::new();
        for depth in 0..K {
            for bucket in buckets.values() {
                if let Some(contact) = bucket.get(depth) {
                    result.push(*contact);
                }
                if result.len() == MAX_CANDIDATES {
                    return result;
                }
            }
        }
        result
    }
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
    pub fn registration_len(&self) -> usize {
        self.registrations.len()
    }

    fn nonce(&mut self) -> [u8; 32] {
        self.serial = self.serial.checked_add(1).expect("nonce counter exhausted");
        let mut h = blake3::Hasher::new_keyed(&self.secret);
        h.update(b"warren:dht-next:nonce:v1");
        h.update(&self.serial.to_le_bytes());
        *h.finalize().as_bytes()
    }

    fn cookie(&self, peer: NodeId, from: SocketAddr, epoch: u64) -> [u8; 32] {
        let mut e = Encoder::new();
        e.raw(b"warren:dht-next:cookie:v2")
            .raw(peer.as_bytes())
            .u64_le(epoch);
        encode_addr(&mut e, from);
        *blake3::keyed_hash(&self.secret, e.as_slice()).as_bytes()
    }

    fn request(
        &mut self,
        contact: Contact,
        body: Body,
        query: Option<u64>,
        now: Time,
        out: &mut Vec<Action>,
    ) -> Result<[u8; 32], Error> {
        if self.pending.len() >= MAX_PENDING {
            return Err(Error::Capacity);
        }
        if contact.id == self.id() || !usable(contact.addr) {
            return Err(Error::Invalid);
        }
        let nonce = self.nonce();
        let peer = self
            .peers
            .get(&(contact.id, contact.addr))
            .filter(|p| p.expires > now.monotonic_ms);
        let retry_delay = peer.map_or(500, |p| p.rtt.timeout());
        let grant = peer.filter(|p| p.token_until > now.monotonic_ms);
        let mut packet = Packet {
            key: self.identity.public(),
            destination: contact.id,
            server: self.server,
            nonce,
            epoch: grant.map_or(0, |p| p.epoch),
            cookie: grant.map_or([0; 32], |p| p.cookie),
            body,
            exchange: Vec::new(),
        };
        let handshake = if self.transport.available(contact.id, contact.addr, now) {
            None
        } else {
            Some(session::start(&mut packet).ok_or(Error::Invalid)?)
        };
        let bytes = self
            .transport
            .encode(&packet, contact.addr, now)
            .unwrap_or_else(|| packet.encode(&self.identity));
        if bytes.len() > protocol::MAX_PACKET {
            return Err(Error::Invalid);
        }
        out.push(Action::Send {
            to: contact.addr,
            bytes,
        });
        self.pending.insert(
            nonce,
            Pending {
                contact,
                packet,
                handshake,
                deadline: now
                    .monotonic_ms
                    .saturating_add((retry_delay * 8).clamp(2000, 8000)),
                retry_at: now.monotonic_ms.saturating_add(retry_delay),
                query,
                challenged: 0,
                sent_at: now.monotonic_ms,
                hedge_at: now.monotonic_ms.saturating_add(retry_delay),
                hedged: false,
                retry_delay,
                retries: 0,
                ambiguous: false,
            },
        );
        Ok(nonce)
    }

    /// Bootstrap hints are candidates, never inserted straight into routing.
    pub fn probe(&mut self, contact: Contact, now: Time) -> Result<Vec<Action>, Error> {
        let mut out = Vec::new();
        self.request(contact, Body::Probe, None, now, &mut out)?;
        Ok(out)
    }

    /// Ask an authenticated peer for the source address of this socket. The
    /// result is a candidate, not proof that other peers can reach that mapping.
    pub fn reflect(
        &mut self,
        contact: Contact,
        now: Time,
    ) -> Result<([u8; 32], Vec<Action>), Error> {
        let mut out = Vec::new();
        let request = self.request(contact, Body::Reflect, None, now, &mut out)?;
        Ok((request, out))
    }

    /// Register with a discovered DHT coordinator. Applications should register
    /// with multiple close nodes and renew before expiry to survive churn.
    pub fn register(
        &mut self,
        coordinator: Contact,
        topic: NodeId,
        now: Time,
    ) -> Result<Vec<Action>, Error> {
        self.register_request(coordinator, topic, now)
            .map(|(_, actions)| actions)
    }

    /// Register now, then renew this topic/coordinator lease until stopped.
    /// Repeating this call for the same endpoint does not reset its schedule.
    pub fn maintain_registration(
        &mut self,
        coordinator: Contact,
        topic: NodeId,
        now: Time,
    ) -> Result<Vec<Action>, Error> {
        self.maintain_registration_for(coordinator, topic, None, now)
    }

    fn maintain_registration_for(
        &mut self,
        coordinator: Contact,
        topic: NodeId,
        publication: Option<NodeId>,
        now: Time,
    ) -> Result<Vec<Action>, Error> {
        if let Some(managed) = self.managed.get_mut(&(topic, coordinator.id)) {
            return if managed.coordinator == coordinator {
                if publication.is_none() {
                    managed.publication = None;
                }
                Ok(Vec::new())
            } else {
                Err(Error::Invalid)
            };
        }
        let (nonce, actions) = self.register_request(coordinator, topic, now)?;
        self.managed.insert(
            (topic, coordinator.id),
            ManagedRegistration {
                publication,
                coordinator,
                pending: Some(nonce),
                next_at: now.monotonic_ms,
                failures: 0,
                lease_expires: None,
            },
        );
        Ok(actions)
    }

    /// Stop future renewal and cancel its pending RPC. Already-issued remote leases
    /// and local signaling authorizations remain valid until their signed expiry.
    pub fn stop_renewing(&mut self, topic: NodeId, coordinator: NodeId) -> bool {
        let Some(managed) = self.managed.remove(&(topic, coordinator)) else {
            return false;
        };
        if let Some(nonce) = managed.pending {
            self.pending.remove(&nonce);
        }
        true
    }

    fn register_request(
        &mut self,
        coordinator: Contact,
        topic: NodeId,
        now: Time,
    ) -> Result<([u8; 32], Vec<Action>), Error> {
        self.expire(now);
        if self.pending.len() >= MAX_PENDING {
            return Err(Error::Capacity);
        }
        let slots: BTreeSet<_> = self
            .authorizations
            .keys()
            .copied()
            .chain(self.managed.keys().copied())
            .chain(self.pending.values().filter_map(|p| match &p.packet.body {
                Body::Register(r) => Some((r.topic, r.coordinator.id)),
                _ => None,
            }))
            .collect();
        if !slots.contains(&(topic, coordinator.id)) && slots.len() >= MAX_REGISTRATIONS {
            return Err(Error::Capacity);
        }
        if self
            .signaling_key_started
            .is_some_and(|started| now.monotonic_ms >= started.saturating_add(300_000))
        {
            self.rotate_signaling_key(now)?;
        }
        self.signaling_key_started.get_or_insert(now.monotonic_ms);
        let record = Record::sign(
            &self.identity,
            topic,
            coordinator,
            now.unix_secs.saturating_add(protocol::LEASE_SECS),
            self.signaling_key
                .public
                .as_slice()
                .try_into()
                .expect("32-byte Noise key"),
        );
        let mut out = Vec::new();
        let nonce = self.request(coordinator, Body::Register(record), None, now, &mut out)?;
        Ok((nonce, out))
    }

    /// Rotate the provider key, retaining up to three previous keys for the
    /// five-minute registration grace period. Fresh registrations use the new key.
    pub fn rotate_signaling_key(&mut self, now: Time) -> Result<(), Error> {
        self.retired_signaling_keys
            .retain(|key| key.expires > now.monotonic_ms);
        if self.retired_signaling_keys.len() >= 3 {
            return Err(Error::Capacity);
        }
        let previous = std::mem::replace(&mut self.signaling_key, signaling::keypair());
        self.retired_signaling_keys.push(signaling::RetiredKey {
            key: previous,
            expires: now.monotonic_ms.saturating_add(300_000),
        });
        self.signaling_key_started = Some(now.monotonic_ms);
        Ok(())
    }

    /// Populate routing state by looking up this node's own identity.
    /// Completion is reported as a normal `LookupDone` event.
    pub fn bootstrap(&mut self, seeds: &[Contact], now: Time) -> Result<(u64, Vec<Action>), Error> {
        self.lookup(self.id(), seeds, now)
    }

    pub fn lookup(
        &mut self,
        target: NodeId,
        seeds: &[Contact],
        now: Time,
    ) -> Result<(u64, Vec<Action>), Error> {
        self.lookup_for(target, seeds, QueryOwner::Application, now)
    }

    /// Cancel an application lookup and its pending RPCs without reporting peer
    /// failures or emitting a completion event. Internal maintenance is unaffected.
    pub fn cancel_lookup(&mut self, query: u64) -> bool {
        if !self
            .queries
            .get(&query)
            .is_some_and(|query| matches!(query.owner, QueryOwner::Application | QueryOwner::Value))
        {
            return false;
        }
        self.queries.remove(&query);
        self.pending
            .retain(|_, pending| pending.query != Some(query));
        true
    }

    /// Retrieve values during traversal. Immutable content completes on its first
    /// verified match; mutable reads finish the frontier and select its highest sequence.
    pub fn lookup_value(
        &mut self,
        key: NodeId,
        seeds: &[Contact],
        now: Time,
    ) -> Result<(u64, Vec<Action>), Error> {
        self.lookup_for(key, seeds, QueryOwner::Value, now)
    }

    /// Fetch a bounded page of signed provider records from one coordinator.
    /// Pass the returned cursor to continue; `None` starts or ends enumeration.
    /// Each page is an independent RPC, with normal timeout and capacity limits.
    pub fn providers_page(
        &mut self,
        coordinator: Contact,
        topic: NodeId,
        after: Option<NodeId>,
        now: Time,
    ) -> Result<([u8; 32], Vec<Action>), Error> {
        let mut actions = Vec::new();
        let request = self.request(
            coordinator,
            Body::GetProviders { topic, after },
            None,
            now,
            &mut actions,
        )?;
        Ok((request, actions))
    }

    fn lookup_for(
        &mut self,
        target: NodeId,
        seeds: &[Contact],
        owner: QueryOwner,
        now: Time,
    ) -> Result<(u64, Vec<Action>), Error> {
        if self.queries.len() >= MAX_QUERIES {
            return Err(Error::Capacity);
        }
        self.query_serial = self.query_serial.checked_add(1).ok_or(Error::Capacity)?;
        let id = self.query_serial;
        let candidates = seeds.iter().copied().take(MAX_CANDIDATES).chain(
            self.routes
                .values()
                .filter(|r| r.expires > now.monotonic_ms)
                .map(|r| r.contact),
        );
        let mut query = Query {
            owner,
            target,
            deadline: now.monotonic_ms.saturating_add(QUERY_MS),
            contacts: BTreeMap::new(),
            records: BTreeSet::new(),
            protected_seeds: BTreeSet::new(),
            value: (owner == QueryOwner::Value).then(ValueLookupResult::default),
        };
        query.add_candidates(self.id(), self.routing_policy, None, candidates);
        if self.routing_policy == RoutingPolicy::Diverse {
            query.protected_seeds = seeds
                .iter()
                .take(MAX_CANDIDATES)
                .filter(|seed| {
                    query
                        .contacts
                        .get(&seed.id)
                        .is_some_and(|c| c.contact == **seed)
                })
                .map(|seed| seed.id)
                .collect();
        }
        self.queries.insert(id, query);
        match owner {
            QueryOwner::Publication(topic) => self.publication_query_started(topic, id),
            QueryOwner::Routing => self.routing_query_started(id),
            QueryOwner::Application | QueryOwner::Value => {}
        }
        let mut out = Vec::new();
        self.drive_queries(now, &mut out);
        Ok((id, out))
    }

    /// Begin an end-to-end encrypted, signed offer via the provider's DHT coordinator.
    pub fn signal(
        &mut self,
        record: Record,
        payload: Vec<u8>,
        now: Time,
    ) -> Result<([u8; 32], Vec<Action>), Error> {
        self.signal_via(&[record], payload, now)
    }

    /// Try up to three independent coordinator registrations, in preference order.
    /// All records must name the same provider, topic, and signaling key.
    pub fn signal_via(
        &mut self,
        records: &[Record],
        payload: Vec<u8>,
        now: Time,
    ) -> Result<([u8; 32], Vec<Action>), Error> {
        let record = records.first().ok_or(Error::Invalid)?.clone();
        if records.len() > MAX_COORDINATORS || payload.len() > protocol::MAX_SIGNAL {
            return Err(Error::Invalid);
        }
        let mut ids = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        if records.iter().any(|r| {
            !r.verify(now.unix_secs)
                || r.provider != record.provider
                || r.topic != record.topic
                || r.signaling_key != record.signaling_key
                || r.coordinator.id == self.id()
                || !usable(r.coordinator.addr)
                || !ids.insert(r.coordinator.id)
                || !endpoints.insert(r.coordinator.addr)
        }) {
            return Err(Error::Invalid);
        }
        if self.outgoing.len() >= MAX_SESSIONS {
            return Err(Error::Capacity);
        }
        let session = self.nonce();
        let target = node_id(record.provider);
        let expires = now.unix_secs.saturating_add(protocol::SIGNAL_SECS).min(
            records
                .iter()
                .map(|r| r.expires)
                .min()
                .expect("nonempty records"),
        );
        let mut signal = Signal::sign(&self.identity, target, session, expires, false, Vec::new());
        let (handshake, ciphertext) =
            signaling::offer(&record, &signal, &payload).ok_or(Error::Invalid)?;
        signal = Signal::sign(&self.identity, target, session, expires, false, ciphertext);
        let coordinator = record.coordinator;
        let mut out = Vec::new();
        self.request(
            coordinator,
            Body::Offer {
                record,
                signal: Box::new(signal.clone()),
            },
            None,
            now,
            &mut out,
        )?;
        self.outgoing.insert(
            session,
            Outgoing {
                alternates: records[1..].to_vec(),
                coordinators: vec![coordinator],
                offer: Some(signal),
                failover_at: now
                    .monotonic_ms
                    .saturating_add(self.failover_delay(coordinator)),
                handshake: Some(handshake),
                deadline: now
                    .monotonic_ms
                    .saturating_add((expires - now.unix_secs) * 1000),
                target,
                expires,
            },
        );
        Ok((session, out))
    }

    /// Only the application can accept an incoming offer; receiving it never
    /// starts a hole punch or sends application data by itself.
    pub fn answer(
        &mut self,
        session: [u8; 32],
        payload: Vec<u8>,
        now: Time,
    ) -> Result<Vec<Action>, Error> {
        if payload.len() > protocol::MAX_SIGNAL {
            return Err(Error::Invalid);
        }
        let incoming = self
            .incoming
            .get_mut(&session)
            .ok_or(Error::UnknownSession)?;
        if incoming.answered || incoming.offer.expires <= now.unix_secs {
            return Err(Error::UnknownSession);
        }
        if self.pending.len() + incoming.coordinators.len() > MAX_PENDING {
            return Err(Error::Capacity);
        }
        let signal = if let Some((signal, digest)) = &incoming.sealed_answer {
            if *digest != crypto::hash(&payload) {
                return Err(Error::Invalid);
            }
            signal.clone()
        } else {
            let mut state = incoming.handshake.take().ok_or(Error::UnknownSession)?;
            let ciphertext = signaling::write(&mut state, &payload).ok_or(Error::Invalid)?;
            let signal = Signal::sign(
                &self.identity,
                node_id(incoming.offer.author),
                session,
                incoming.offer.expires,
                true,
                ciphertext,
            );
            incoming.sealed_answer = Some((signal.clone(), crypto::hash(&payload)));
            signal
        };
        let coordinators = incoming.coordinators.clone();
        let mut out = Vec::new();
        for coordinator in coordinators {
            self.request(
                coordinator,
                Body::Answer(signal.clone()),
                None,
                now,
                &mut out,
            )?;
        }
        self.incoming
            .get_mut(&session)
            .expect("incoming exists")
            .answered = true;
        Ok(out)
    }

    /// Deliver one datagram. A fixed budget limits parsing/signature work per
    /// monotonic second, with a 64-packet allowance per network prefix.
    /// Invalid/oversized traffic consumes that allowance too.
    pub fn receive(&mut self, from: SocketAddr, bytes: &[u8], now: Time) -> Vec<Action> {
        let mut out = Vec::new();
        if now.monotonic_ms / 1000 > self.budget_second {
            self.budget_second = now.monotonic_ms / 1000;
            self.budget_used = 0;
            self.budget_prefixes.clear();
        }
        if self.budget_used >= 256 || !usable(from) {
            return out;
        }
        let allowance = self
            .budget_prefixes
            .entry(routing::network_prefix(from))
            .or_default();
        if *allowance >= 64 {
            return out;
        }
        *allowance += 1;
        self.budget_used += 1;
        let Some(packet) = self
            .transport
            .decode(bytes, from, self.id(), now)
            .or_else(|| Packet::decode(bytes))
        else {
            return out;
        };
        if packet.destination != self.id() || node_id(packet.key) == self.id() {
            return out;
        }
        self.expire(now);
        if packet.body.response() {
            self.response(from, packet, now, &mut out);
        } else {
            let peer = node_id(packet.key);
            let epoch = now.monotonic_ms / COOKIE_MS;
            let valid = packet.epoch <= epoch
                && epoch - packet.epoch <= 1
                && blake3::Hash::from(packet.cookie) == self.cookie(peer, from, packet.epoch);
            if !valid {
                let mut challenge = self.reply(&packet, Body::Challenge);
                challenge.epoch = epoch;
                challenge.cookie = self.cookie(peer, from, epoch);
                let bytes = challenge.encode(&self.identity);
                out.push(Action::Send { to: from, bytes });
                return out;
            }
            let replay_key = (peer, packet.nonce);
            if let Some(replay) = self.replay.get(&replay_key) {
                if replay.from == from {
                    out.push(Action::Send {
                        to: from,
                        bytes: replay
                            .packet
                            .as_ref()
                            .and_then(|p| self.transport.encode(p, from, now))
                            .unwrap_or_else(|| replay.response.clone()),
                    });
                }
                return out;
            }
            if self.replay.len() >= MAX_REPLAYS
                || self.replay.keys().filter(|(id, _)| *id == peer).count() >= 256
                || self
                    .replay
                    .values()
                    .filter(|r| routing::network_prefix(r.from) == routing::network_prefix(from))
                    .count()
                    >= 512
            {
                return out;
            }
            let sender = Contact::new(peer, from);
            // Only an active, authenticated return-path exchange earns admission.
            if packet.server {
                self.admit(sender, now);
            }
            if let Some(body) = self.handle_request(sender, &packet.body, now, &mut out) {
                let mut reply = self.reply(&packet, body);
                if let Some(exchange) = self.transport.accept(&packet, from, now) {
                    reply.exchange = exchange;
                }
                let response = self
                    .transport
                    .encode(&reply, from, now)
                    .unwrap_or_else(|| reply.encode(&self.identity));
                debug_assert!(response.len() <= protocol::MAX_PACKET);
                self.replay.insert(
                    replay_key,
                    Replay {
                        from,
                        response: response.clone(),
                        packet: reply.exchange.is_empty().then_some(reply),
                        expires: packet.epoch.saturating_add(2).saturating_mul(COOKIE_MS),
                    },
                );
                out.push(Action::Send {
                    to: from,
                    bytes: response,
                });
            }
        }
        self.drive_queries(now, &mut out);
        out
    }

    fn reply(&self, request: &Packet, body: Body) -> Packet {
        Packet {
            key: self.identity.public(),
            destination: node_id(request.key),
            server: self.server,
            nonce: request.nonce,
            epoch: 0,
            cookie: [0; 32],
            body,
            exchange: Vec::new(),
        }
    }

    fn response(&mut self, from: SocketAddr, packet: Packet, now: Time, out: &mut Vec<Action>) {
        let Some(p) = self.pending.get_mut(&packet.nonce) else {
            return;
        };
        if p.contact.id != node_id(packet.key)
            || p.contact.addr != from
            || p.deadline <= now.monotonic_ms
        {
            return;
        }
        if matches!(packet.body, Body::Challenge) {
            if p.challenged >= 2
                || (p.packet.epoch == packet.epoch && p.packet.cookie == packet.cookie)
            {
                return;
            }
            p.challenged += 1;
            let sample = if p.ambiguous {
                None
            } else {
                Some(now.monotonic_ms.saturating_sub(p.sent_at))
            };
            if self.peers.contains_key(&(p.contact.id, from)) || self.peers.len() < MAX_PEERS {
                let peer = self
                    .peers
                    .entry((p.contact.id, from))
                    .or_insert_with(|| Peer {
                        epoch: 0,
                        cookie: [0; 32],
                        token_until: 0,
                        expires: now.monotonic_ms.saturating_add(300_000),
                        rtt: Rtt::default(),
                    });
                if let Some(sample) = sample {
                    peer.rtt.observe(sample);
                } else {
                    peer.rtt.ambiguous(p.retry_delay);
                }
                peer.epoch = packet.epoch;
                peer.cookie = packet.cookie;
                peer.token_until = now.monotonic_ms.saturating_add(COOKIE_MS);
                peer.expires = now.monotonic_ms.saturating_add(300_000);
                p.retry_delay = peer.rtt.timeout();
            }
            p.sent_at = now.monotonic_ms;
            p.hedge_at = now.monotonic_ms.saturating_add(p.retry_delay);
            p.hedged = false;
            p.retry_at = now.monotonic_ms.saturating_add(p.retry_delay);
            p.ambiguous = false;
            p.packet.epoch = packet.epoch;
            p.packet.cookie = packet.cookie;
            out.push(Action::Send {
                to: from,
                bytes: p.packet.encode(&self.identity),
            });
            return;
        }
        if !matches!(
            (&p.packet.body, &packet.body),
            (Body::Reflect, Body::Reflected(_))
                | (Body::Find(_), Body::Nodes { .. })
                | (Body::GetProviders { .. }, Body::ProviderPage { .. })
                | (Body::PutValue { .. }, Body::ValueStored(_))
                | (Body::GetValue(_), Body::ValueResult(_))
                | (Body::FindValue(_), Body::ValueNodes { .. })
        ) && (matches!(
            p.packet.body,
            Body::Reflect
                | Body::Find(_)
                | Body::GetProviders { .. }
                | Body::PutValue { .. }
                | Body::GetValue(_)
                | Body::FindValue(_)
        ) || !matches!(packet.body, Body::Ack))
        {
            return;
        }
        if matches!(&packet.body, Body::Reflected(address) if !usable(*address)) {
            return;
        }
        if matches!(&p.packet.body, Body::Register(r) if !r.verify(now.unix_secs)) {
            return;
        }
        if let (Body::GetProviders { topic, after }, Body::ProviderPage { records, next }) =
            (&p.packet.body, &packet.body)
        {
            let mut previous = *after;
            for record in records {
                let id = node_id(record.provider);
                if record.topic != *topic
                    || record.coordinator != p.contact
                    || !record.verify(now.unix_secs)
                    || previous.is_some_and(|last| id <= last)
                {
                    return;
                }
                previous = Some(id);
            }
            if next.is_some() && (records.is_empty() || *next != previous) {
                return;
            }
        }
        if let (Body::GetValue(key), Body::ValueResult(Some(value)))
        | (
            Body::FindValue(key),
            Body::ValueNodes {
                value: Some(value), ..
            },
        ) = (&p.packet.body, &packet.body)
        {
            if value.key() != *key || !value.verify(now) {
                return;
            }
        }
        if !packet.exchange.is_empty() {
            let Some(state) = p.handshake.take() else {
                return;
            };
            if self.transport.finish(state, &packet, from, now).is_none() {
                return;
            }
        }
        let p = self.pending.remove(&packet.nonce).expect("pending exists");
        if let Some(peer) = self.peers.get_mut(&(p.contact.id, from)) {
            if p.ambiguous {
                peer.rtt.ambiguous(p.retry_delay);
            } else {
                peer.rtt.observe(now.monotonic_ms.saturating_sub(p.sent_at));
            }
            peer.expires = now.monotonic_ms.saturating_add(300_000);
        }
        if packet.server {
            self.admit(p.contact, now);
        }
        let routing_probe = self.routing_response(packet.nonce, packet.server);
        match p.packet.body {
            Body::Reflect => {
                let Body::Reflected(address) = packet.body else {
                    unreachable!()
                };
                out.push(Action::event(Event::ObservedAddress {
                    request: packet.nonce,
                    reflector: p.contact,
                    address,
                }));
                return;
            }
            Body::PutValue { value, .. } => {
                let Body::ValueStored(stored) = packet.body else {
                    unreachable!()
                };
                out.push(Action::event(Event::ValueStored {
                    request: packet.nonce,
                    key: value.key(),
                    stored,
                }));
                return;
            }
            Body::GetValue(key) => {
                let Body::ValueResult(value) = packet.body else {
                    unreachable!()
                };
                out.push(Action::event(Event::Value {
                    request: packet.nonce,
                    coordinator: p.contact,
                    key,
                    value,
                }));
                return;
            }
            Body::GetProviders { topic, .. } => {
                let Body::ProviderPage { records, next } = packet.body else {
                    unreachable!()
                };
                out.push(Action::event(Event::ProviderPage {
                    request: packet.nonce,
                    coordinator: p.contact,
                    topic,
                    records,
                    next,
                }));
                return;
            }
            Body::Probe if !routing_probe => out.push(Action::event(Event::Ready(p.contact))),
            Body::Register(record) => {
                if !record.verify(now.unix_secs) {
                    return;
                }
                let key = (record.topic, record.coordinator.id);
                if let Some(managed) = self.managed.get_mut(&key) {
                    if managed.pending == Some(packet.nonce) {
                        managed.pending = None;
                        managed.failures = 0;
                        managed.lease_expires = Some(record.expires);
                        let jitter =
                            u64::from_le_bytes(packet.nonce[..8].try_into().unwrap()) % 15_000;
                        let remaining = (record.expires - now.unix_secs).saturating_mul(1000);
                        managed.next_at = now
                            .monotonic_ms
                            .saturating_add(remaining.saturating_sub(90_000 + jitter).max(1000));
                    }
                }
                if self
                    .authorizations
                    .get(&key)
                    .is_some_and(|old| old.record.expires > record.expires)
                {
                    return;
                }
                if self.authorizations.contains_key(&key)
                    || self.authorizations.len() < MAX_REGISTRATIONS
                {
                    self.authorizations.insert(
                        key,
                        Registration {
                            record: record.clone(),
                            endpoint: p.contact,
                        },
                    );
                    out.push(Action::event(Event::Registered(record)));
                }
            }
            _ => {}
        }
        if let Some(query) = p.query.and_then(|id| self.queries.get_mut(&id)) {
            if let Some(candidate) = query.contacts.get_mut(&p.contact.id) {
                candidate.status = Status::Done;
            }
            if let Body::ValueNodes { contacts, value } = packet.body {
                query.add_candidates(
                    node_id(self.identity.public()),
                    self.routing_policy,
                    Some(p.contact.id),
                    contacts,
                );
                query.value.as_mut().expect("value query").observe(value);
            } else if let Body::Nodes { contacts, records } = packet.body {
                query.add_candidates(
                    node_id(self.identity.public()),
                    self.routing_policy,
                    Some(p.contact.id),
                    contacts,
                );
                let records: Vec<_> = records
                    .into_iter()
                    .filter(|r| r.topic == query.target && r.verify(now.unix_secs))
                    .filter(|r| {
                        query
                            .records
                            .insert((node_id(r.provider), r.coordinator.id))
                    })
                    .collect();
                if !records.is_empty() && query.owner == QueryOwner::Application {
                    out.push(Action::event(Event::Providers {
                        query: p.query.unwrap(),
                        records,
                    }));
                }
            }
        }
    }

    fn handle_request(
        &mut self,
        sender: Contact,
        body: &Body,
        now: Time,
        out: &mut Vec<Action>,
    ) -> Option<Body> {
        #[cfg(feature = "test-support")]
        if self.test_has_written && matches!(body, Body::GetValue(_)) {
            match &self.test_storage.read_after_write {
                Some(testing::ReadFault::Missing) => return Some(Body::ValueResult(None)),
                Some(testing::ReadFault::Silent) => return None,
                Some(testing::ReadFault::Value(value)) => {
                    return Some(Body::ValueResult(Some(value.clone())))
                }
                None => {}
            }
        }
        match body {
            Body::Reflect if self.server => Some(Body::Reflected(sender.addr)),
            Body::PutValue { value, cas } if self.server => Some(Body::ValueStored(
                self.store_value(sender, value, *cas, now),
            )),
            Body::GetValue(key) if self.server => {
                Some(Body::ValueResult(self.stored_value(*key, now)))
            }
            Body::Probe => Some(Body::Ack),
            Body::GetProviders { topic, after } if self.server => {
                let mut records: Vec<_> = self
                    .registrations
                    .values()
                    .filter(|r| r.record.topic == *topic && r.record.coordinator.id == self.id())
                    .map(|r| &r.record)
                    .filter(|r| after.is_none_or(|id| node_id(r.provider) > id))
                    .collect();
                records.sort_by_key(|r| node_id(r.provider));
                let more = records.len() > protocol::MAX_RECORDS;
                let records: Vec<_> = records
                    .into_iter()
                    .take(protocol::MAX_RECORDS)
                    .cloned()
                    .collect();
                let next = more.then(|| node_id(records.last().unwrap().provider));
                Some(Body::ProviderPage { records, next })
            }
            Body::FindValue(key) if self.server => {
                let value = self.stored_value(*key, now);
                let limit = if value.is_some() {
                    protocol::MAX_VALUE_CONTACTS
                } else {
                    protocol::MAX_CONTACTS
                };
                Some(Body::ValueNodes {
                    contacts: self.closest(*key, limit),
                    value,
                })
            }
            Body::Find(target) if self.server => {
                let contacts = self.closest(*target, protocol::MAX_CONTACTS);
                let records = self
                    .registrations
                    .values()
                    .filter(|r| r.record.topic == *target && r.record.coordinator.id == self.id())
                    .map(|r| r.record.clone())
                    .take(protocol::MAX_RECORDS)
                    .collect();
                Some(Body::Nodes { contacts, records })
            }
            Body::Register(record) if self.server => {
                if node_id(record.provider) != sender.id
                    || record.coordinator.id != self.id()
                    || !record.verify(now.unix_secs)
                {
                    return None;
                }
                let key = (record.topic, sender.id);
                if let Some(old) = self.registrations.get(&key) {
                    if old.record.expires > record.expires {
                        return None;
                    }
                } else if self.registrations.len() >= MAX_REGISTRATIONS
                    || self
                        .registrations
                        .values()
                        .filter(|r| r.endpoint.id == sender.id)
                        .count()
                        >= 16
                    || self
                        .registrations
                        .values()
                        .filter(|r| {
                            routing::network_prefix(r.endpoint.addr)
                                == routing::network_prefix(sender.addr)
                        })
                        .count()
                        >= 64
                {
                    return None;
                }
                self.registrations.insert(
                    key,
                    Registration {
                        record: record.clone(),
                        endpoint: sender,
                    },
                );
                Some(Body::Ack)
            }
            Body::Offer { record, signal } if self.server => {
                if !record.verify(now.unix_secs)
                    || !signal.verify(now.unix_secs)
                    || signal.answer
                    || node_id(signal.author) != sender.id
                    || signal.recipient != node_id(record.provider)
                    || record.coordinator.id != self.id()
                    || signal.expires > record.expires
                {
                    return None;
                }
                let registration = self.registrations.get(&(record.topic, signal.recipient))?;
                if registration.record.coordinator != record.coordinator
                    || registration.record.expires < record.expires
                    || self.exchanges.contains_key(&signal.session)
                    || self.exchanges.len() >= MAX_SESSIONS
                    || self
                        .exchanges
                        .values()
                        .filter(|e| e.initiator.id == sender.id)
                        .count()
                        >= 8
                    || self
                        .exchanges
                        .values()
                        .filter(|e| {
                            routing::network_prefix(e.initiator.addr)
                                == routing::network_prefix(sender.addr)
                        })
                        .count()
                        >= 32
                {
                    return None;
                }
                let target = registration.endpoint;
                self.request(
                    target,
                    Body::Forward(signal.as_ref().clone()),
                    None,
                    now,
                    out,
                )
                .ok()?;
                self.exchanges.insert(
                    signal.session,
                    Exchange {
                        initiator: sender,
                        target,
                        expires: signal.expires,
                        answered: false,
                    },
                );
                Some(Body::Ack)
            }
            Body::Forward(signal) => {
                if !signal.verify(now.unix_secs) || signal.recipient != self.id() {
                    return None;
                }
                if signal.answer {
                    let pending = self.outgoing.get_mut(&signal.session)?;
                    if !pending.coordinators.contains(&sender)
                        || pending.target != node_id(signal.author)
                        || pending.expires != signal.expires
                    {
                        return None;
                    }
                    let opened = signaling::read(pending.handshake.as_mut()?, signal)?;
                    self.outgoing.remove(&signal.session);
                    self.cancel_offers(signal.session);
                    out.push(Action::event(Event::Answered(opened)));
                } else {
                    let authorized = self.authorizations.values().any(|r| {
                        node_id(r.record.provider) == self.id()
                            && r.endpoint == sender
                            && r.record.expires >= signal.expires
                    });
                    if !authorized {
                        return None;
                    }
                    if let Some(incoming) = self.incoming.get(&signal.session) {
                        if incoming.offer != *signal {
                            return None;
                        }
                        let known = incoming.coordinators.contains(&sender);
                        if !known
                            && (incoming.coordinators.len() >= MAX_COORDINATORS
                                || incoming
                                    .coordinators
                                    .iter()
                                    .any(|c| c.id == sender.id || c.addr == sender.addr))
                        {
                            return None;
                        }
                        if incoming.answered {
                            let answer = incoming.sealed_answer.as_ref()?.0.clone();
                            self.request(sender, Body::Answer(answer), None, now, out)
                                .ok()?;
                        }
                        if !known {
                            self.incoming
                                .get_mut(&signal.session)?
                                .coordinators
                                .push(sender);
                        }
                        return Some(Body::Ack);
                    }
                    if self.incoming.len() >= MAX_SESSIONS
                        || self
                            .incoming
                            .values()
                            .filter(|i| i.offer.author == signal.author)
                            .count()
                            >= 8
                    {
                        return None;
                    }
                    let (handshake, opened) = signaling::receive_offer(
                        &self.signaling_key.private,
                        signal,
                    )
                    .or_else(|| {
                        self.retired_signaling_keys
                            .iter()
                            .rev()
                            .filter(|key| key.expires > now.monotonic_ms)
                            .find_map(|key| signaling::receive_offer(&key.key.private, signal))
                    })?;
                    self.incoming.insert(
                        signal.session,
                        Incoming {
                            handshake: Some(handshake),
                            coordinators: vec![sender],
                            sealed_answer: None,
                            offer: signal.clone(),
                            answered: false,
                        },
                    );
                    out.push(Action::event(Event::Incoming {
                        coordinator: sender,
                        signal: opened,
                    }));
                }
                Some(Body::Ack)
            }
            Body::Answer(signal) if self.server => {
                if !signal.verify(now.unix_secs)
                    || !signal.answer
                    || node_id(signal.author) != sender.id
                {
                    return None;
                }
                let exchange = self.exchanges.get(&signal.session)?;
                if exchange.target != sender
                    || exchange.initiator.id != signal.recipient
                    || exchange.expires != signal.expires
                    || exchange.answered
                {
                    return None;
                }
                let initiator = exchange.initiator;
                self.request(initiator, Body::Forward(signal.clone()), None, now, out)
                    .ok()?;
                self.exchanges.get_mut(&signal.session)?.answered = true;
                Some(Body::Ack)
            }
            _ => None,
        }
    }

    fn admit(&mut self, contact: Contact, now: Time) {
        let bucket = self.id().distance(&contact.id).leading_zeros();
        if let Some(old) = self.routes.get_mut(&contact.id) {
            // A still-live identity cannot silently move addresses via an old packet.
            if old.contact.addr == contact.addr {
                old.expires = now.monotonic_ms.saturating_add(protocol::LEASE_SECS * 1000);
            }
            return;
        }
        if !self.routing_allows(contact, now)
            || self.routes.len() >= MAX_ROUTING
            || self
                .routes
                .keys()
                .filter(|id| self.id().distance(id).leading_zeros() == bucket)
                .count()
                >= K
        {
            self.cache_replacement(contact, now);
            return;
        }
        self.routes.insert(
            contact.id,
            Route {
                contact,
                expires: now.monotonic_ms.saturating_add(protocol::LEASE_SECS * 1000),
            },
        );
        self.routing_admitted(contact, now);
    }

    fn closest(&self, target: NodeId, limit: usize) -> Vec<Contact> {
        let mut contacts: Vec<_> = self.routes.values().map(|r| r.contact).collect();
        contacts.sort_by_key(|c| c.id.distance(&target));
        contacts.truncate(limit);
        contacts
    }

    fn expire(&mut self, now: Time) {
        self.retired_signaling_keys
            .retain(|key| key.expires > now.monotonic_ms);
        self.expire_values(now);
        self.transport.expire(now);
        self.routing_expire(now);
        self.routes.retain(|_, r| r.expires > now.monotonic_ms);
        self.peers.retain(|_, p| p.expires > now.monotonic_ms);
        self.registrations
            .retain(|_, r| r.record.expires > now.unix_secs);
        self.authorizations
            .retain(|_, r| r.record.expires > now.unix_secs);
        self.replay.retain(|_, r| r.expires > now.monotonic_ms);
        self.exchanges.retain(|_, e| e.expires > now.unix_secs);
        self.incoming.retain(|_, i| i.offer.expires > now.unix_secs);
    }

    /// Call at the deadline returned by `poll_timeout`. Retried RPCs
    /// retain their nonce; cached replies recover loss without repeating effects.
    pub fn tick(&mut self, now: Time) -> Vec<Action> {
        self.expire(now);
        let mut out = Vec::new();
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline <= now.monotonic_ms)
            .map(|(n, _)| *n)
            .collect();
        for nonce in expired {
            let p = self.pending.remove(&nonce).unwrap();
            if let Some(q) = p.query.and_then(|id| self.queries.get_mut(&id)) {
                if let Some(candidate) = q.contacts.get_mut(&p.contact.id) {
                    candidate.status = Status::Failed;
                }
            }
            let exploration = p
                .query
                .and_then(|id| self.queries.get(&id))
                .is_some_and(|q| q.owner == QueryOwner::Routing);
            if !self.routing_failed(nonce) && !exploration {
                out.push(Action::event(Event::RpcTimedOut(nonce)));
            }
        }
        for p in self.pending.values_mut() {
            if p.hedge_at <= now.monotonic_ms {
                p.hedged = true;
            }
            if p.retry_at <= now.monotonic_ms && p.retries < MAX_RETRIES {
                p.retries += 1;
                p.ambiguous = true;
                p.retry_delay = (p.retry_delay * 2).min(4000);
                p.retry_at = now.monotonic_ms.saturating_add(p.retry_delay);
                if p.retries >= 2 && p.handshake.is_none() {
                    self.transport
                        .forget_preferred(p.contact.id, p.contact.addr);
                    p.handshake = session::start(&mut p.packet);
                }
                let bytes = self
                    .transport
                    .encode(&p.packet, p.contact.addr, now)
                    .unwrap_or_else(|| p.packet.encode(&self.identity));
                out.push(Action::Send {
                    to: p.contact.addr,
                    bytes,
                });
            }
        }
        let sessions: Vec<_> = self.outgoing.keys().copied().collect();
        for session in sessions {
            let s = &self.outgoing[&session];
            if s.expires <= now.unix_secs || s.deadline <= now.monotonic_ms {
                self.outgoing.remove(&session);
                self.cancel_offers(session);
                out.push(Action::event(Event::SignalTimedOut(session)));
            } else if !s.alternates.is_empty() && s.failover_at <= now.monotonic_ms {
                let record = s.alternates[0].clone();
                let signal = s.offer.clone().expect("outgoing offer");
                let coordinator = record.coordinator;
                let delay = self.failover_delay(coordinator);
                if self
                    .request(
                        coordinator,
                        Body::Offer {
                            record,
                            signal: Box::new(signal),
                        },
                        None,
                        now,
                        &mut out,
                    )
                    .is_ok()
                {
                    let s = self.outgoing.get_mut(&session).unwrap();
                    s.alternates.remove(0);
                    s.coordinators.push(coordinator);
                    s.failover_at = now.monotonic_ms.saturating_add(delay);
                } else {
                    self.outgoing.get_mut(&session).unwrap().failover_at =
                        now.monotonic_ms.saturating_add(200);
                }
            }
        }
        self.drive_queries(now, &mut out);
        self.renew_registrations(now, &mut out);
        self.discover_publications(now, &mut out);
        self.refresh_routes(now, &mut out);
        self.explore_routes(now, &mut out);
        out
    }

    fn renew_registrations(&mut self, now: Time, out: &mut Vec<Action>) {
        let keys: Vec<_> = self.managed.keys().copied().collect();
        for key in keys {
            let m = self.managed.get_mut(&key).unwrap();
            if let Some(nonce) = m.pending {
                if self.pending.contains_key(&nonce) {
                    continue;
                }
                m.pending = None;
                m.failures = m.failures.saturating_add(1);
                let delay = (1000u64 << m.failures.min(5)).min(30_000);
                m.next_at = now.monotonic_ms.saturating_add(delay);
            }
            if m.lease_expires
                .is_some_and(|expires| expires <= now.unix_secs)
            {
                m.lease_expires = None;
                m.next_at = now.monotonic_ms;
            }
            if m.next_at > now.monotonic_ms {
                continue;
            }
            let coordinator = m.coordinator;
            match self.register_request(coordinator, key.0, now) {
                Ok((nonce, actions)) => {
                    self.managed.get_mut(&key).unwrap().pending = Some(nonce);
                    out.extend(actions);
                }
                Err(_) => {
                    self.managed.get_mut(&key).unwrap().next_at =
                        now.monotonic_ms.saturating_add(1000);
                }
            }
        }
    }

    fn failover_delay(&self, coordinator: Contact) -> u64 {
        self.peers
            .get(&(coordinator.id, coordinator.addr))
            .map_or(2000, |p| (p.rtt.timeout() * 4).clamp(500, 2000))
    }

    fn cancel_offers(&mut self, session: [u8; 32]) {
        self.pending.retain(|_, p| {
            !matches!(&p.packet.body,
            Body::Offer { signal, .. } if signal.session == session)
        });
    }

    /// Earliest monotonic deadline; an idle core needs no periodic wakeup.
    pub fn poll_timeout(&self) -> Option<u64> {
        self.pending
            .values()
            .flat_map(|p| {
                [
                    p.deadline,
                    if p.retries < MAX_RETRIES {
                        p.retry_at
                    } else {
                        p.deadline
                    },
                    if p.hedged { p.deadline } else { p.hedge_at },
                ]
            })
            .chain(
                self.managed
                    .values()
                    .filter(|m| m.pending.is_none())
                    .map(|m| m.next_at),
            )
            .chain(self.publication_timeout())
            .chain(self.routing_deadline())
            .chain(self.queries.values().map(|q| q.deadline))
            .chain(self.retired_signaling_keys.iter().map(|key| key.expires))
            .chain(self.outgoing.values().map(|s| {
                if s.alternates.is_empty() {
                    s.deadline
                } else {
                    s.deadline.min(s.failover_at)
                }
            }))
            .min()
    }

    fn drive_queries(&mut self, now: Time, out: &mut Vec<Action>) {
        let ids: Vec<_> = self.queries.keys().copied().collect();
        for id in ids {
            let q = &self.queries[&id];
            let target = q.target;
            let timed_out = q.deadline <= now.monotonic_ms;
            let mut order: Vec<_> = q
                .contacts
                .values()
                .filter(|c| c.status != Status::Failed)
                .copied()
                .collect();
            order.sort_by_key(|c| c.contact.id.distance(&target));
            let in_flight = order.iter().filter(|c| c.status == Status::Flight).count();
            let responsive = self
                .pending
                .values()
                .filter(|p| p.query == Some(id) && !p.hedged)
                .count();
            let slots = ALPHA
                .saturating_sub(responsive)
                .min(MAX_FLIGHT.saturating_sub(in_flight));
            let fresh: Vec<_> = order
                .iter()
                .enumerate()
                .filter(|(rank, c)| {
                    c.status == Status::Fresh
                        && (*rank < K || q.protected_seeds.contains(&c.contact.id))
                })
                .map(|(_, c)| c.contact)
                .collect();
            let fresh = q.select_candidates(fresh, slots, self.routing_policy);
            let immutable_found = q
                .value
                .as_ref()
                .is_some_and(|v| matches!(v.value, Some(Value::Immutable(_))));
            if immutable_found || timed_out || (in_flight == 0 && fresh.is_empty()) {
                let owner = q.owner;
                let closest: Vec<_> = order
                    .into_iter()
                    .filter(|c| c.status == Status::Done)
                    .take(K)
                    .map(|c| c.contact)
                    .collect();
                let query = self.queries.remove(&id).unwrap();
                self.pending.retain(|_, p| p.query != Some(id));
                match owner {
                    QueryOwner::Publication(topic) => {
                        self.publication_result(topic, &closest, now, out)
                    }
                    QueryOwner::Routing => self.routing_query_finished(now),
                    QueryOwner::Value => {
                        let mut result = query.value.expect("value query");
                        result.timed_out = timed_out;
                        if result.value.as_ref().is_some_and(|v| !v.verify(now)) {
                            result.value = None;
                            result.conflicting = false;
                        }
                        out.push(Action::event(Event::ValueLookupDone {
                            query: id,
                            key: target,
                            result,
                        }));
                    }
                    QueryOwner::Application => out.push(Action::event(Event::LookupDone {
                        query: id,
                        closest,
                        timed_out,
                    })),
                }
                continue;
            }
            let value_query = q.owner == QueryOwner::Value;
            for contact in fresh {
                let body = if value_query {
                    Body::FindValue(target)
                } else {
                    Body::Find(target)
                };
                if self.request(contact, body, Some(id), now, out).is_ok() {
                    let query = self.queries.get_mut(&id).unwrap();
                    if let Some(value) = &mut query.value {
                        value.attempted += 1;
                    }
                    query.contacts.get_mut(&contact.id).unwrap().status = Status::Flight;
                }
            }
        }
    }
}

fn usable(addr: SocketAddr) -> bool {
    addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast()
}

#[cfg(test)]
mod attacks;
