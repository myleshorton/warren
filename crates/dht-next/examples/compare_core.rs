//! Paired, seeded lookup and DHT-signaling measurements. No real network traffic.
//! Run: cargo run --release -p dht-next --example compare_core -- 20
use crypto::Keypair;
use dht_next::Time;
use dht_next::{node_id, Action, Contact, Dht, Event, NodeId};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::net::SocketAddr;
use std::time::Instant;

const STEP: u64 = 10;
const START: u64 = 120_000;
const LIMIT: u64 = 45_000;

#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    rtt: u64,
    loss: u64,
    dead: u64,
}
const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "healthy_40ms",
        rtt: 40,
        loss: 0,
        dead: 0,
    },
    Scenario {
        name: "wan_200ms",
        rtt: 200,
        loss: 0,
        dead: 0,
    },
    Scenario {
        name: "slow_800ms",
        rtt: 800,
        loss: 0,
        dead: 0,
    },
    Scenario {
        name: "loss_10pct",
        rtt: 40,
        loss: 10,
        dead: 0,
    },
    Scenario {
        name: "loss_30pct",
        rtt: 40,
        loss: 30,
        dead: 0,
    },
    Scenario {
        name: "dead_30pct",
        rtt: 40,
        loss: 0,
        dead: 30,
    },
];

enum Core {
    Legacy(Box<swarm::Dht>),
    Next(Box<Dht>),
}
type Delivery = Reverse<(u64, u64, usize, usize, Vec<u8>)>;

struct Sim {
    cores: Vec<Core>,
    contacts: Vec<Contact>,
    queue: BinaryHeap<Delivery>,
    serial: u64,
    ordinals: BTreeMap<(usize, usize), u64>,
    scenario: Scenario,
    seed: u64,
    now: u64,
    measuring: bool,
    signaling: bool,
    target: NodeId,
    started_signal: bool,
    done: Option<(bool, u64)>,
    first_provider: Option<u64>,
    dead: Vec<bool>,
    packets: u64,
    bytes: u64,
}

fn random(seed: u64, a: u64, b: u64, c: u64) -> u64 {
    let mut bytes = [0; 32];
    for (chunk, value) in bytes.chunks_mut(8).zip([seed, a, b, c]) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    u64::from_le_bytes(crypto::hash(&bytes)[..8].try_into().unwrap())
}

impl Sim {
    fn new(next: bool, signaling: bool, scenario: Scenario, seed: u64) -> Self {
        let count = if signaling { 3 } else { 25 };
        let keys: Vec<_> = (0..count)
            .map(|i| {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&seed.to_le_bytes());
                bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                Keypair::from_seed(&crypto::hash(&bytes))
            })
            .collect();
        let contacts: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                Contact::new(
                    node_id(k.public()),
                    format!("192.0.2.{}:4000", i + 1).parse().unwrap(),
                )
            })
            .collect();
        let cores = keys
            .into_iter()
            .enumerate()
            .map(|(i, k)| {
                let server = i != 0 && (!signaling || i == 1);
                if next {
                    let mut secret = [0; 32];
                    secret[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                    secret[8..16].copy_from_slice(&seed.to_le_bytes());
                    Core::Next(Box::new(Dht::with_routing_policy(
                        k,
                        crypto::hash(&secret),
                        server,
                        dht_next::RoutingPolicy::Unrestricted,
                    )))
                } else {
                    let mut dht = swarm::Dht::new(node_id(k.public()));
                    dht.pin_firewall(if server {
                        swarm::Firewall::Open
                    } else {
                        swarm::Firewall::Consistent
                    });
                    Core::Legacy(Box::new(dht))
                }
            })
            .collect();
        let target_index = if signaling {
            2
        } else {
            1 + (random(seed, 0, 0, 0) % 24) as usize
        };
        let target = contacts[target_index].id;
        let mut sim = Self {
            cores,
            contacts,
            queue: BinaryHeap::new(),
            serial: 0,
            ordinals: BTreeMap::new(),
            scenario,
            seed,
            now: START - 10_000,
            measuring: false,
            signaling,
            target,
            started_signal: false,
            done: None,
            first_provider: None,
            dead: vec![false; count],
            packets: 0,
            bytes: 0,
        };
        // Symmetric ring edges give both implementations the same initial routing
        // graph. The requester is a non-routing client seeded with two servers.
        let mut edges = vec![(0, 1)];
        if signaling {
            edges.push((2, 1));
        } else {
            edges.push((0, 9));
            for i in 1..count {
                for offset in [1, 3, 21, 23] {
                    edges.push((i, 1 + (i - 1 + offset) % 24));
                }
            }
        }
        for (source, destination) in &edges {
            let contact = sim.contacts[*destination];
            match &mut sim.cores[*source] {
                Core::Legacy(d) => d.add_contact(contact),
                Core::Next(d) => {
                    let actions = d
                        .probe(contact, Time::new(sim.now, sim.now / 1000))
                        .unwrap();
                    sim.next_actions(*source, actions);
                }
            }
        }
        sim.advance(START - 5000);
        for (i, core) in sim.cores.iter().enumerate() {
            let expected = edges.iter().filter(|(source, _)| *source == i).count();
            let actual = match core {
                Core::Legacy(d) => d.routing_len(),
                Core::Next(d) => d.routing_len(),
            };
            assert_eq!(
                actual, expected,
                "initial routing graph differs at node {i}"
            );
        }
        if signaling {
            match &mut sim.cores[2] {
                Core::Legacy(d) => {
                    d.announce(target, sim.now);
                    sim.legacy_actions(2);
                }
                Core::Next(d) => {
                    let actions = d
                        .register(sim.contacts[1], target, Time::new(sim.now, sim.now / 1000))
                        .unwrap();
                    sim.next_actions(2, actions);
                }
            }
        }
        sim.advance(START);
        assert!(
            sim.queue.is_empty(),
            "setup traffic must finish before measurement"
        );
        if !signaling {
            for i in 1..count {
                sim.dead[i] =
                    i != target_index && random(seed, i as u64, 1, 0) % 100 < scenario.dead;
            }
        }
        sim
    }

    fn send(&mut self, source: usize, to: SocketAddr, bytes: Vec<u8>) {
        let destination = self
            .contacts
            .iter()
            .position(|c| c.addr == to)
            .expect("known endpoint");
        if self.measuring {
            self.packets += 1;
            self.bytes += bytes.len() as u64;
            let ordinal = self.ordinals.entry((source, destination)).or_default();
            let lost = random(self.seed, source as u64, destination as u64, *ordinal) % 100
                < self.scenario.loss;
            *ordinal += 1;
            if lost || self.dead[destination] {
                return;
            }
        }
        self.serial += 1;
        let delay = if self.measuring {
            self.scenario.rtt / 2
        } else {
            20
        };
        self.queue.push(Reverse((
            self.now + delay,
            self.serial,
            source,
            destination,
            bytes,
        )));
    }

    fn next_actions(&mut self, source: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send { to, bytes } => self.send(source, to, bytes),
                Action::Event(event) if self.measuring => match *event {
                    Event::LookupDone { closest, .. } if source == 0 && !self.signaling => {
                        self.done = Some((
                            closest.iter().any(|c| c.id == self.target),
                            self.now - START,
                        ));
                    }
                    Event::Providers { records, .. }
                        if source == 0 && self.signaling && !self.started_signal =>
                    {
                        if let Some(record) = records
                            .into_iter()
                            .find(|r| node_id(r.provider) == self.target)
                        {
                            self.first_provider = Some(self.now - START);
                            self.started_signal = true;
                            let Core::Next(d) = &mut self.cores[0] else {
                                unreachable!()
                            };
                            let (_, actions) = d
                                .signal(record, vec![7; 16], Time::new(self.now, self.now / 1000))
                                .unwrap();
                            self.next_actions(0, actions);
                        }
                    }
                    Event::LookupDone { .. }
                        if source == 0 && self.signaling && !self.started_signal =>
                    {
                        self.done = Some((false, self.now - START));
                    }
                    Event::Incoming { signal, .. } if source == 2 && self.signaling => {
                        let Core::Next(d) = &mut self.cores[2] else {
                            unreachable!()
                        };
                        let actions = d
                            .answer(
                                signal.envelope.session,
                                vec![8; 16],
                                Time::new(self.now, self.now / 1000),
                            )
                            .unwrap();
                        self.next_actions(2, actions);
                    }
                    Event::Answered(_) if source == 0 => self.done = Some((true, self.now - START)),
                    Event::SignalTimedOut(_) if source == 0 => {
                        self.done = Some((false, self.now - START))
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    fn legacy_actions(&mut self, source: usize) {
        loop {
            let Core::Legacy(d) = &mut self.cores[source] else {
                unreachable!()
            };
            let Some(tx) = d.poll_transmit() else {
                break;
            };
            self.send(source, tx.to, tx.data);
        }
        loop {
            let Core::Legacy(d) = &mut self.cores[source] else {
                unreachable!()
            };
            let Some(event) = d.poll_event() else {
                break;
            };
            if !self.measuring {
                continue;
            }
            match event {
                swarm::Event::QueryFinished { closest, .. } if source == 0 && !self.signaling => {
                    self.done = Some((
                        closest.iter().any(|c| c.id == self.target),
                        self.now - START,
                    ));
                }
                swarm::Event::IncomingConnect { initiator, .. } if source == 2 => {
                    d.accept_connect(initiator, vec![self.contacts[2].addr], self.now);
                    self.legacy_actions(source);
                }
                swarm::Event::Connected {
                    outcome, lookup_ms, ..
                } if source == 0 => {
                    self.first_provider = lookup_ms;
                    self.done = Some((
                        matches!(
                            outcome,
                            swarm::ConnectOutcome::Direct | swarm::ConnectOutcome::Punched
                        ),
                        self.now - START,
                    ));
                }
                _ => {}
            }
        }
    }

    fn advance(&mut self, until: u64) {
        while self.now < until && (!self.measuring || self.done.is_none()) {
            self.now += STEP;
            while self
                .queue
                .peek()
                .is_some_and(|Reverse((at, ..))| *at <= self.now)
            {
                let Reverse((_, _, source, destination, bytes)) = self.queue.pop().unwrap();
                if self.dead[destination] {
                    continue;
                }
                let from = self.contacts[source].addr;
                match &mut self.cores[destination] {
                    Core::Legacy(d) => {
                        d.handle_input(from, &bytes, self.now);
                        self.legacy_actions(destination);
                    }
                    Core::Next(d) => {
                        let actions = d.receive(from, &bytes, Time::new(self.now, self.now / 1000));
                        self.next_actions(destination, actions);
                    }
                }
            }
            for i in 0..self.cores.len() {
                if self.dead[i] {
                    continue;
                }
                match &mut self.cores[i] {
                    Core::Legacy(d) => {
                        d.handle_timeout(self.now);
                        self.legacy_actions(i);
                    }
                    Core::Next(d) => {
                        let actions = d.tick(Time::new(self.now, self.now / 1000));
                        self.next_actions(i, actions);
                    }
                }
            }
        }
    }

    fn run(&mut self) -> (bool, u64, u128) {
        self.measuring = true;
        let started = Instant::now();
        match &mut self.cores[0] {
            Core::Legacy(d) => {
                if self.signaling {
                    d.connect(self.target, vec![self.contacts[0].addr], self.now);
                } else {
                    d.find_node(self.target, self.now);
                }
                self.legacy_actions(0);
            }
            Core::Next(d) => {
                let (_, actions) = d
                    .lookup(self.target, &[], Time::new(self.now, self.now / 1000))
                    .unwrap();
                self.next_actions(0, actions);
            }
        }
        self.advance(START + LIMIT);
        let (success, elapsed) = self.done.unwrap_or((false, LIMIT));
        (success, elapsed, started.elapsed().as_micros())
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("failover") {
        compare_failover();
        return;
    }
    let trials = std::env::args()
        .nth(1)
        .map(|n| n.parse::<u64>().expect("integer trial count"))
        .unwrap_or(20);
    assert!((1..=1000).contains(&trials));
    println!("scenario,workload,engine,seed,success,elapsed_ms,packets,bytes,discovery_ms,host_us");
    for scenario in SCENARIOS {
        for signaling in [false, true] {
            if signaling && scenario.dead != 0 {
                continue;
            }
            for seed in 0..trials {
                for next in [false, true] {
                    let mut sim = Sim::new(next, signaling, *scenario, seed);
                    let (success, elapsed, host_us) = sim.run();
                    println!(
                        "{},{},{},{},{},{},{},{},{},{}",
                        scenario.name,
                        if signaling { "signaling" } else { "lookup" },
                        if next { "next" } else { "legacy" },
                        seed,
                        success,
                        elapsed,
                        sim.packets,
                        sim.bytes,
                        sim.first_provider
                            .map(|v| v.to_string())
                            .unwrap_or_default(),
                        host_us
                    );
                }
            }
        }
    }
}

/// A separate paired experiment: one coordinator versus automatic alternate paths.
fn compare_failover() {
    let trials = std::env::args()
        .nth(2)
        .map(|n| n.parse::<u64>().unwrap())
        .unwrap_or(100);
    assert!((1..=1000).contains(&trials));
    println!("scenario,loss_pct,mode,seed,success,elapsed_ms,packets,bytes,incoming_events");
    for scenario in ["healthy", "first_dead", "first_return_broken"] {
        for loss in [0, 10, 30] {
            for seed in 0..trials {
                for automatic in [false, true] {
                    failover_trial(scenario, loss, seed, automatic);
                }
            }
        }
    }
}

fn failover_trial(scenario: &str, loss: u64, seed: u64, automatic: bool) {
    let mut cores: Vec<_> = (0..4u8)
        .map(|i| {
            let mut bytes = [i; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            Dht::with_routing_policy(
                Keypair::from_seed(&bytes),
                crypto::hash(&bytes),
                i == 1 || i == 3,
                dht_next::RoutingPolicy::Unrestricted,
            )
        })
        .collect();
    let contacts: Vec<_> = cores
        .iter()
        .enumerate()
        .map(|(i, d)| Contact::new(d.id(), format!("192.0.2.{}:4000", i + 1).parse().unwrap()))
        .collect();
    let mut queue: BinaryHeap<Delivery> = BinaryHeap::new();
    let mut serial = 0;
    let mut ordinals: BTreeMap<(usize, usize), u64> = BTreeMap::new();
    let mut records = Vec::new();
    let mut actions = std::collections::VecDeque::new();
    let mut packets = 0;
    let mut bytes_sent = 0;
    let mut incoming = 0;
    let mut result = None;
    let setup = START - 10_000;
    for coordinator in [1, 3] {
        actions.extend(
            cores[0]
                .probe(contacts[coordinator], Time::new(setup, setup / 1000))
                .unwrap()
                .into_iter()
                .map(|a| (0, a)),
        );
        actions.extend(
            cores[2]
                .register(
                    contacts[coordinator],
                    contacts[2].id,
                    Time::new(setup, setup / 1000),
                )
                .unwrap()
                .into_iter()
                .map(|a| (2, a)),
        );
    }
    for now in (setup..=START + 21_000).step_by(STEP as usize) {
        let time = Time::new(now, now / 1000);
        if now == START {
            assert_eq!(records.len(), 2);
            assert!(queue.is_empty());
            let count = if automatic { 2 } else { 1 };
            let (_, out) = cores[0]
                .signal_via(&records[..count], vec![7; 16], time)
                .unwrap();
            actions.extend(out.into_iter().map(|a| (0, a)));
        }
        while queue.peek().is_some_and(|Reverse((at, ..))| *at <= now) {
            let Reverse((_, _, source, destination, bytes)) = queue.pop().unwrap();
            let out = cores[destination].receive(contacts[source].addr, &bytes, time);
            actions.extend(out.into_iter().map(|a| (destination, a)));
        }
        for (i, core) in cores.iter_mut().enumerate() {
            actions.extend(core.tick(time).into_iter().map(|a| (i, a)));
        }
        while let Some((source, action)) = actions.pop_front() {
            match action {
                Action::Send { to, bytes } => {
                    let destination = contacts.iter().position(|c| c.addr == to).unwrap();
                    if now >= START {
                        packets += 1;
                        bytes_sent += bytes.len();
                        let ordinal = ordinals.entry((source, destination)).or_default();
                        let dropped =
                            random(seed, source as u64, destination as u64, *ordinal) % 100 < loss;
                        *ordinal += 1;
                        if dropped
                            || (scenario == "first_dead" && (source == 1 || destination == 1))
                            || (scenario == "first_return_broken"
                                && source == 1
                                && destination == 0)
                        {
                            continue;
                        }
                    }
                    serial += 1;
                    queue.push(Reverse((now + 20, serial, source, destination, bytes)));
                }
                Action::Event(event) => match *event {
                    Event::Registered(r) if now < START => records.push(r),
                    Event::Incoming { signal, .. } if source == 2 => {
                        incoming += 1;
                        let out = cores[2]
                            .answer(signal.envelope.session, vec![8; 16], time)
                            .unwrap();
                        actions.extend(out.into_iter().map(|a| (2, a)));
                    }
                    Event::Answered(_) if source == 0 => result = Some((true, now - START)),
                    Event::SignalTimedOut(_) if source == 0 => result = Some((false, now - START)),
                    _ => {}
                },
            }
        }
        if result.is_some() {
            break;
        }
    }
    assert!(incoming <= 1, "duplicate application offer");
    let (success, elapsed) = result.expect("bounded completion");
    println!(
        "{scenario},{loss},{},{seed},{success},{elapsed},{packets},{bytes_sent},{incoming}",
        if automatic { "failover" } else { "single" }
    );
}
