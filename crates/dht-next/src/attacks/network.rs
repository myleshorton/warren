//! Seeded, in-memory malicious-peer scenarios. No sockets or public traffic.
use super::*;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap};

type Delivery = Reverse<(u64, u64, usize, usize, Vec<u8>)>;
struct Network {
    nodes: Vec<Dht>,
    contacts: Vec<Contact>,
    queue: BinaryHeap<Delivery>,
    events: Vec<(usize, Event)>,
    discard: BTreeSet<usize>,
    blackhole: BTreeSet<usize>,
    now: u64,
    seed: u64,
    serial: u64,
    packets: usize,
    bytes: usize,
    dropped: usize,
    peak_pending: usize,
    contacted: BTreeSet<usize>,
}
impl Network {
    fn new(count: usize, seed: u64, policy: RoutingPolicy, concentration: &str) -> Self {
        let nodes: Vec<_> = (0..count)
            .map(|i| {
                let mut material = [0; 32];
                material[..8].copy_from_slice(&seed.to_le_bytes());
                material[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                Dht::with_routing_policy(
                    Keypair::from_seed(&crypto::hash(&material)),
                    material,
                    i >= 2,
                    policy,
                )
            })
            .collect();
        let contacts = nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let ip = match concentration {
                    "ip" if i >= 2 => [10, 1, 0, 1],
                    "prefix" if i >= 2 => [10, 1, 0, i as u8],
                    _ => [10, 2, i as u8, 1],
                };
                Contact::new(node.id(), SocketAddr::from((ip, 4000 + i as u16)))
            })
            .collect();
        Self {
            nodes,
            contacts,
            queue: BinaryHeap::new(),
            events: vec![],
            discard: BTreeSet::new(),
            blackhole: BTreeSet::new(),
            now: 100_000,
            seed,
            serial: 0,
            packets: 0,
            bytes: 0,
            dropped: 0,
            peak_pending: 0,
            contacted: BTreeSet::new(),
        }
    }
    fn time(&self) -> Time {
        Time::new(self.now, self.now / 1000)
    }
    fn actions(&mut self, source: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Event(event) => {
                    let session = match &*event {
                        Event::Incoming { signal, .. } if source == 1 => {
                            assert_eq!(signal.payload, b"offer");
                            Some(signal.envelope.session)
                        }
                        _ => None,
                    };
                    self.events.push((source, *event));
                    if let Some(session) = session {
                        let now = self.time();
                        let reply = self.nodes[source]
                            .answer(session, b"answer".to_vec(), now)
                            .unwrap();
                        self.actions(source, reply);
                    }
                }
                Action::Send { to, bytes } => {
                    assert!(bytes.len() <= protocol::MAX_PACKET);
                    let dest = self
                        .contacts
                        .iter()
                        .position(|c| c.addr == to)
                        .expect("known endpoint");
                    self.packets += 1;
                    self.bytes += bytes.len();
                    if source == 0 {
                        self.contacted.insert(dest);
                    }
                    // Coordinators remain responsive to the caller but withhold
                    // their provider-bound traffic, including retransmissions.
                    if self.blackhole.contains(&source) && dest == 1 {
                        self.dropped += 1;
                        continue;
                    }
                    self.serial += 1;
                    let mut material = [0; 24];
                    material[..8].copy_from_slice(&self.seed.to_le_bytes());
                    material[8..16].copy_from_slice(&self.serial.to_le_bytes());
                    material[16..].copy_from_slice(&(source as u64).to_le_bytes());
                    let delay = 25 + u64::from(crypto::hash(&material)[0] % 25);
                    self.queue.push(Reverse((
                        self.now + delay,
                        self.serial,
                        source,
                        dest,
                        bytes,
                    )));
                }
            }
        }
        self.peak_pending = self
            .peak_pending
            .max(self.nodes.iter().map(Dht::pending_len).sum());
        assert!(self.nodes.iter().all(|n| n.pending_len() <= MAX_PENDING));
        assert!(self.nodes.iter().all(|n| n
            .queries
            .values()
            .all(|q| q.contacts.len() <= MAX_CANDIDATES)));
    }
    fn settle(&mut self) {
        let deadline = self.now + 65_000;
        let mut steps = 0;
        while !self.queue.is_empty()
            || self
                .nodes
                .iter()
                .any(|n| n.pending_len() != 0 || !n.outgoing.is_empty() || !n.queries.is_empty())
        {
            steps += 1;
            assert!(steps < 100_000, "unbounded simulation");
            let next = self
                .queue
                .peek()
                .map(|p| p.0 .0)
                .into_iter()
                .chain(self.nodes.iter().filter_map(Dht::poll_timeout))
                .min()
                .expect("pending timer");
            assert!(
                next >= self.now && next <= deadline,
                "operation failed to terminate"
            );
            self.now = next;
            let now = self.time();
            for i in 0..self.nodes.len() {
                if self.nodes[i].poll_timeout().is_some_and(|t| t <= self.now) {
                    let actions = self.nodes[i].tick(now);
                    self.actions(i, actions);
                }
            }
            while self.queue.peek().is_some_and(|p| p.0 .0 <= self.now) {
                let Reverse((_, _, source, dest, bytes)) = self.queue.pop().unwrap();
                let actions = self.nodes[dest].receive(self.contacts[source].addr, &bytes, now);
                // The malicious owner accepts a normal signed write, generates
                // its real acknowledgement, then deliberately discards storage.
                if self.discard.contains(&dest) {
                    self.nodes[dest].values.clear();
                }
                self.actions(dest, actions);
            }
        }
    }
    fn probe(&mut self, source: usize, dest: usize) {
        let now = self.time();
        let actions = self.nodes[source].probe(self.contacts[dest], now).unwrap();
        self.actions(source, actions);
        self.settle();
    }
    fn register(&mut self, dest: usize) -> Record {
        let now = self.time();
        let actions = self.nodes[1]
            .register(self.contacts[dest], self.contacts[1].id, now)
            .unwrap();
        self.actions(1, actions);
        self.settle();
        self.events
            .iter()
            .rev()
            .find_map(|(i, e)| match e {
                Event::Registered(r) if *i == 1 => Some(r.clone()),
                _ => None,
            })
            .expect("registration acknowledged")
    }
    fn measure(&mut self) -> u64 {
        assert!(self.queue.is_empty());
        assert!(self.nodes.iter().all(|n| n.pending_len() == 0));
        self.events.clear();
        self.packets = 0;
        self.bytes = 0;
        self.dropped = 0;
        self.peak_pending = 0;
        self.contacted.clear();
        self.now
    }
    fn row(
        &self,
        scenario: &str,
        policy: RoutingPolicy,
        start: u64,
        success: bool,
        claims: usize,
        observed: usize,
    ) {
        println!("ADVERSARIAL,{scenario},{},{policy:?},{success},{claims},{observed},{},{},{},{},{},{},{}", self.seed, self.now - start, self.packets, self.bytes, self.dropped, self.peak_pending, self.contacted.len(), self.nodes[0].routing_len());
    }
}

fn referrals(seed: u64, mode: &str, policy: RoutingPolicy) {
    let mut n = Network::new(35, seed, policy, "spread");
    // Attackers advertise only their collaborating identities. Honest node 2
    // knows the provider but is deliberately absent from every attacker table.
    for i in 3..35 {
        for offset in 1..=4 {
            n.probe(i, 3 + (i - 3 + offset) % 32);
        }
    }
    n.register(2);
    let seeds = match mode {
        "honest" => vec![n.contacts[2]],
        "independent" => vec![n.contacts[3], n.contacts[2]],
        "captured" => vec![n.contacts[3]],
        _ => unreachable!(),
    };
    let start = n.measure();
    let now = n.time();
    let (query, actions) = n.nodes[0].lookup(n.contacts[1].id, &seeds, now).unwrap();
    n.actions(0, actions);
    n.settle();
    let found = n.events.iter().any(|(i,e)| matches!(e, Event::Providers { query: q, records } if *i == 0 && *q == query && !records.is_empty()));
    assert!(n
        .events
        .iter()
        .any(|(i, e)| matches!(e, Event::LookupDone { query: q, .. } if *i == 0 && *q == query)));
    assert_eq!(
        found,
        mode != "captured",
        "independent bootstrap determines reachability"
    );
    if mode != "honest" {
        assert!(
            n.contacted.iter().any(|i| *i >= 4),
            "attack must exercise referrals beyond its seed"
        );
    }
    n.row(
        &format!("referral_{mode}_seed"),
        policy,
        start,
        found,
        0,
        usize::from(found),
    );
}
fn seed_frontier(seed: u64, policy: RoutingPolicy) {
    let mut n = Network::new(35, seed, policy, "spread");
    let topic = n.contacts[1].id;
    // Choose the farthest real identity as the only useful starting point.
    // Every closer server authenticates but withholds the provider's existence.
    let honest = (2..35)
        .max_by_key(|i| n.contacts[*i].id.distance(&topic))
        .unwrap();
    n.register(honest);
    let seeds = n.contacts[2..].to_vec();
    let start = n.measure();
    let now = n.time();
    let (query, actions) = n.nodes[0].lookup(topic, &seeds, now).unwrap();
    n.actions(0, actions);
    n.settle();
    let found = n.events.iter().any(|(i,e)| matches!(e, Event::Providers { query: q, records } if *i == 0 && *q == query && !records.is_empty()));
    assert!(n
        .events
        .iter()
        .any(|(i, e)| matches!(e, Event::LookupDone { query: q, .. } if *i == 0 && *q == query)));
    assert_eq!(found, policy == RoutingPolicy::Diverse);
    assert_eq!(
        n.contacted.contains(&honest),
        policy == RoutingPolicy::Diverse
    );
    n.row(
        "seed_outside_frontier",
        policy,
        start,
        found,
        33,
        usize::from(found),
    );
}

fn signaling(seed: u64, bad: usize) {
    let policy = RoutingPolicy::Diverse;
    let mut n = Network::new(5, seed, policy, "spread");
    let records: Vec<_> = (2..5).map(|i| n.register(i)).collect();
    n.blackhole.extend(2..2 + bad);
    let start = n.measure();
    let now = n.time();
    let (session, actions) = n.nodes[0]
        .signal_via(&records, b"offer".to_vec(), now)
        .unwrap();
    n.actions(0, actions);
    n.settle();
    let success = n.events.iter().any(|(i,e)| matches!(e, Event::Answered(s) if *i == 0 && s.envelope.session == session && s.payload == b"answer"));
    assert_eq!(success, bad < 3);
    if bad == 3 {
        assert!(n
            .events
            .iter()
            .any(|(i, e)| matches!(e, Event::SignalTimedOut(s) if *i == 0 && *s == session)));
    }
    if bad > 0 {
        assert!(n.dropped > 0);
    }
    n.row(
        &format!("signal_{bad}_blackholes"),
        policy,
        start,
        success,
        3,
        usize::from(success),
    );
}
fn storage(seed: u64, bad: usize) {
    let policy = RoutingPolicy::Diverse;
    let mut n = Network::new(5, seed, policy, "spread");
    n.discard.extend(2..2 + bad);
    let value = Value::Immutable(b"must actually remain retrievable".to_vec());
    let start = n.measure();
    for i in 2..5 {
        let now = n.time();
        let (_, actions) = n.nodes[0]
            .put_value(n.contacts[i], value.clone(), None, now)
            .unwrap();
        n.actions(0, actions);
        n.settle();
    }
    let claims = n
        .events
        .iter()
        .filter(|(i, e)| *i == 0 && matches!(e, Event::ValueStored { stored: true, .. }))
        .count();
    assert_eq!(claims, 3);
    for i in 2..5 {
        let now = n.time();
        let (_, actions) = n.nodes[0]
            .get_value(n.contacts[i], value.key(), now)
            .unwrap();
        n.actions(0, actions);
        n.settle();
    }
    let observed = n
        .events
        .iter()
        .filter(|(i, e)| *i == 0 && matches!(e, Event::Value { value: Some(v), .. } if *v == value))
        .count();
    assert_eq!(observed, 3 - bad);
    let now = n.time();
    let (query, actions) = n.nodes[0]
        .lookup_value(value.key(), &n.contacts[2..5], now)
        .unwrap();
    n.actions(0, actions);
    n.settle();
    let result = n
        .events
        .iter()
        .find_map(|(i, e)| match e {
            Event::ValueLookupDone {
                query: q, result, ..
            } if *i == 0 && *q == query => Some(result),
            _ => None,
        })
        .expect("value lookup completes");
    let success = result.value.as_ref() == Some(&value);
    assert_eq!(success, bad < 3);
    n.row(
        &format!("storage_{bad}_discarders"),
        policy,
        start,
        success,
        claims,
        observed,
    );
}
fn concentration(seed: u64, group: &str, policy: RoutingPolicy) {
    let mut n = Network::new(50, seed, policy, group);
    let start = n.measure();
    for i in 2..50 {
        n.probe(0, i);
    }
    let authenticated = n
        .events
        .iter()
        .filter(|(i, event)| *i == 0 && matches!(event, Event::Ready(_)))
        .count();
    assert_eq!(
        authenticated, 48,
        "admission limits must not be confused with failed authentication"
    );
    let admitted = n.nodes[0].routing_len();
    assert!(admitted > 0);
    if policy == RoutingPolicy::Diverse {
        match group {
            "ip" => assert_eq!(admitted, 1),
            "prefix" => assert!(admitted <= 8),
            _ => assert!(admitted > 8),
        }
    } else {
        assert!(admitted > 8);
    }
    n.row(
        &format!("identity_{group}"),
        policy,
        start,
        true,
        48,
        admitted,
    );
}
#[test]
fn adversarial_matrix() {
    let trials: u64 = std::env::var("WARREN_ADVERSARIAL_TRIALS")
        .map_or(3, |v| v.parse().expect("integer trials"));
    assert!((1..=100).contains(&trials));
    println!("ADVERSARIAL,scenario,seed,policy,operation_succeeded,claims,observed,elapsed_ms,packets,bytes,dropped,peak_pending,caller_contacts,caller_routes");
    for seed in 0..trials {
        for policy in [RoutingPolicy::Diverse, RoutingPolicy::Unrestricted] {
            for mode in ["honest", "independent", "captured"] {
                referrals(seed, mode, policy);
            }
            seed_frontier(seed, policy);
            for group in ["ip", "prefix", "spread"] {
                concentration(seed, group, policy);
            }
        }
        for bad in 0..=3 {
            signaling(seed, bad);
            storage(seed, bad);
        }
    }
}
