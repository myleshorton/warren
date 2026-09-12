//! Seeded topology, abrupt churn, discovery, and encrypted DHT signaling trials.
//! Run: cargo run --release -p dht-next --example topology -- 5 256
use crypto::Keypair;
use dht_next::{Action, Contact, Dht, Event, NodeId, Record, RoutingPolicy, Time};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::net::SocketAddr;

type Delivery = Reverse<(u64, u64, usize, usize, Vec<u8>)>;
fn random(seed: u64, a: u64, b: u64, c: u64) -> u64 {
    let mut bytes = [0; 32];
    for (chunk, value) in bytes.chunks_mut(8).zip([seed, a, b, c]) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    u64::from_le_bytes(crypto::hash(&bytes)[..8].try_into().unwrap())
}

struct Network {
    nodes: Vec<Dht>,
    contacts: Vec<Contact>,
    endpoints: BTreeMap<SocketAddr, usize>,
    queue: BinaryHeap<Delivery>,
    ordinal: BTreeMap<(usize, usize), u64>,
    serial: u64,
    now: u64,
    seed: u64,
    measuring: bool,
    loss: u64,
    dead: BTreeSet<usize>,
    caller: usize,
    provider: usize,
    records: BTreeMap<NodeId, Record>,
    first_provider: Option<u64>,
    lookup_done: Option<u64>,
    lookup_timed_out: bool,
    closest: Vec<Contact>,
    signal_done: Option<u64>,
    finished: bool,
    packets: u64,
    bytes: u64,
    peak_pending: usize,
}
impl Network {
    fn time(&self) -> Time {
        Time::new(self.now, self.now / 1000)
    }
    fn new(count: usize, cluster: usize, seed: u64, policy: RoutingPolicy) -> Self {
        let nodes: Vec<_> = (0..count + 2)
            .map(|i| {
                let mut material = [0; 32];
                material[..8].copy_from_slice(&seed.to_le_bytes());
                material[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                let key = Keypair::from_seed(&crypto::hash(&material));
                material[31] = 1;
                Dht::with_routing_policy(key, crypto::hash(&material), i < count, policy)
            })
            .collect();
        let contacts: Vec<_> = nodes
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let prefix = i / cluster;
                let address = SocketAddr::from((
                    [
                        10,
                        (prefix / 256) as u8,
                        (prefix % 256) as u8,
                        (i % cluster + 1) as u8,
                    ],
                    4000,
                ));
                Contact::new(d.id(), address)
            })
            .collect();
        Self {
            endpoints: contacts
                .iter()
                .enumerate()
                .map(|(i, c)| (c.addr, i))
                .collect(),
            nodes,
            contacts,
            queue: BinaryHeap::new(),
            ordinal: BTreeMap::new(),
            serial: 0,
            now: 100_000,
            seed,
            measuring: false,
            loss: 0,
            dead: BTreeSet::new(),
            caller: count,
            provider: count + 1,
            records: BTreeMap::new(),
            first_provider: None,
            lookup_done: None,
            lookup_timed_out: false,
            closest: vec![],
            signal_done: None,
            finished: false,
            packets: 0,
            bytes: 0,
            peak_pending: 0,
        }
    }
    fn actions(&mut self, source: usize, actions: Vec<Action>) {
        let mut work: VecDeque<_> = actions.into_iter().map(|a| (source, a)).collect();
        while let Some((source, action)) = work.pop_front() {
            match action {
                Action::Send { to, bytes } => {
                    let destination = self.endpoints[&to];
                    if self.measuring {
                        self.packets += 1;
                        self.bytes += bytes.len() as u64;
                        let ordinal = self.ordinal.entry((source, destination)).or_default();
                        let lost = random(self.seed, source as u64, destination as u64, *ordinal)
                            % 100
                            < self.loss;
                        *ordinal += 1;
                        if lost || self.dead.contains(&source) || self.dead.contains(&destination) {
                            continue;
                        }
                    }
                    self.serial += 1;
                    let delay = if self.measuring {
                        20 + random(self.seed, source as u64, destination as u64, 999) % 180
                    } else {
                        10
                    };
                    self.queue.push(Reverse((
                        self.now + delay,
                        self.serial,
                        source,
                        destination,
                        bytes,
                    )));
                }
                Action::Event(event) if self.measuring => {
                    let more = match *event {
                        Event::Providers { records, .. } if source == self.caller => {
                            self.first_provider.get_or_insert(self.now);
                            for record in records {
                                self.records.insert(record.coordinator.id, record);
                            }
                            vec![]
                        }
                        Event::LookupDone {
                            closest, timed_out, ..
                        } if source == self.caller => {
                            self.lookup_done = Some(self.now);
                            self.lookup_timed_out = timed_out;
                            self.closest = closest;
                            let records: Vec<_> = self.records.values().take(3).cloned().collect();
                            if records.is_empty() {
                                self.finished = true;
                                vec![]
                            } else {
                                let now = self.time();
                                self.nodes[source]
                                    .signal_via(&records, b"topology offer".to_vec(), now)
                                    .unwrap()
                                    .1
                            }
                        }
                        Event::Incoming { signal, .. } if source == self.provider => {
                            assert_eq!(signal.payload, b"topology offer");
                            let now = self.time();
                            self.nodes[source]
                                .answer(signal.envelope.session, b"topology answer".to_vec(), now)
                                .unwrap()
                        }
                        Event::Answered(signal) if source == self.caller => {
                            assert_eq!(signal.payload, b"topology answer");
                            self.signal_done = Some(self.now);
                            self.finished = true;
                            vec![]
                        }
                        Event::SignalTimedOut(_) if source == self.caller => {
                            self.finished = true;
                            vec![]
                        }
                        _ => vec![],
                    };
                    work.extend(more.into_iter().map(|a| (source, a)));
                }
                _ => {}
            }
        }
        self.peak_pending = self
            .peak_pending
            .max(self.nodes.iter().map(Dht::pending_len).sum());
    }
    fn run(&mut self, until: u64) {
        while !self.finished {
            let next_packet = self.queue.peek().map(|p| p.0 .0);
            let next_timer = self
                .nodes
                .iter()
                .enumerate()
                .filter(|(i, _)| !self.dead.contains(i))
                .filter_map(|(_, d)| d.poll_timeout())
                .min();
            let Some(next) = next_packet.into_iter().chain(next_timer).min() else {
                break;
            };
            if next > until {
                break;
            }
            assert!(next >= self.now, "timer moved backwards");
            self.now = next;
            for i in 0..self.nodes.len() {
                if !self.dead.contains(&i)
                    && self.nodes[i]
                        .poll_timeout()
                        .is_some_and(|at| at <= self.now)
                {
                    let now = self.time();
                    let actions = self.nodes[i].tick(now);
                    self.actions(i, actions);
                }
            }
            while self.queue.peek().is_some_and(|p| p.0 .0 <= self.now) {
                let Reverse((_, _, source, destination, bytes)) = self.queue.pop().unwrap();
                if self.dead.contains(&source) || self.dead.contains(&destination) {
                    continue;
                }
                let now = self.time();
                let actions =
                    self.nodes[destination].receive(self.contacts[source].addr, &bytes, now);
                self.actions(destination, actions);
            }
        }
        self.now = self.now.max(until);
    }
}

#[derive(Clone, Copy)]
struct Topology {
    count: usize,
    cluster: usize,
    loss: u64,
    churn: u64,
    join_rounds: usize,
}
fn trial(topology: Topology, seeds: usize, seed: u64, policy: RoutingPolicy) {
    let Topology {
        count,
        cluster,
        loss,
        churn,
        join_rounds,
    } = topology;
    let mut n = Network::new(count, cluster, seed, policy);
    for i in 0..count {
        let mut peers = BTreeSet::from([(i + 1) % count]);
        for j in 0..7 {
            peers.insert(random(seed, i as u64, j, 42) as usize % count);
        }
        peers.remove(&i);
        for peer in peers {
            let now = n.time();
            let actions = n.nodes[i].probe(n.contacts[peer], now).unwrap();
            n.actions(i, actions);
        }
    }
    n.run(105_000);
    assert!(n.queue.is_empty());
    for _ in 0..join_rounds {
        for i in 0..count {
            let now = n.time();
            let (_, actions) = n.nodes[i].bootstrap(&[], now).unwrap();
            n.actions(i, actions);
        }
        n.run(n.now + 45_000);
        assert!(n.queue.is_empty());
    }
    let topic = n.contacts[n.provider].id;
    let mut nearest: Vec<_> = (0..count).collect();
    nearest.sort_by_key(|i| n.contacts[*i].id.distance(&topic));
    let coordinators: BTreeSet<_> = nearest[..3].iter().copied().collect();
    for i in &coordinators {
        let now = n.time();
        let actions = n.nodes[n.provider]
            .register(n.contacts[*i], topic, now)
            .unwrap();
        n.actions(n.provider, actions);
    }
    n.run(n.now + 5000);
    assert!(n.queue.is_empty());
    assert_eq!(n.nodes.iter().map(Dht::pending_len).sum::<usize>(), 0);
    n.dead = (0..count)
        .filter(|i| !coordinators.contains(i) && random(seed, *i as u64, 0, 73) % 100 < churn)
        .collect();
    let live_nearest: BTreeSet<_> = nearest
        .iter()
        .filter(|i| !n.dead.contains(i))
        .take(20)
        .map(|i| n.contacts[*i].id)
        .collect();
    let mut bootstrap: Vec<_> = (0..count).collect();
    bootstrap.sort_by_key(|i| random(seed, *i as u64, 0, 84));
    let bootstrap: Vec<_> = bootstrap
        .into_iter()
        .take(seeds)
        .map(|i| n.contacts[i])
        .collect();
    let live_bootstrap = bootstrap
        .iter()
        .filter(|c| !n.dead.contains(&n.endpoints[&c.addr]))
        .count();
    n.loss = loss;
    n.measuring = true;
    n.peak_pending = 0;
    let start = n.now;
    let now = n.time();
    let (_, actions) = n.nodes[n.caller].lookup(topic, &bootstrap, now).unwrap();
    n.actions(n.caller, actions);
    n.run(start + 65_000);
    let recall = n
        .closest
        .iter()
        .filter(|c| live_nearest.contains(&c.id))
        .count();
    let elapsed = |time: Option<u64>| time.map_or_else(String::new, |t| (t - start).to_string());
    println!(
        "{count},{cluster},{loss},{churn},{seeds},{seed},{policy:?},{join_rounds},{live_bootstrap},{},{},{},{},{},{},{},{},{},{}",
        !n.records.is_empty(),
        n.signal_done.is_some(),
        elapsed(n.first_provider),
        elapsed(n.lookup_done),
        n.lookup_timed_out,
        elapsed(n.signal_done),
        recall,
        n.packets,
        n.bytes,
        n.peak_pending
    );
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let trials: u64 = args.get(1).map_or(5, |s| s.parse().unwrap());
    let max_nodes: usize = args.get(2).map_or(256, |s| s.parse().unwrap());
    let join_rounds: usize = args.get(3).map_or(2, |s| s.parse().unwrap());
    assert!(join_rounds <= 4);
    assert!((1..=1000).contains(&trials) && (64..=4096).contains(&max_nodes));
    println!("nodes,peers_per_prefix,loss_pct,churn_pct,bootstrap_count,seed,policy,join_rounds,live_bootstrap,provider_found,signal_succeeded,first_provider_ms,lookup_ms,lookup_timed_out,signal_ms,nearest20_found,packets,bytes,peak_pending");
    for count in [64, max_nodes].into_iter().collect::<BTreeSet<_>>() {
        for (cluster, loss, churn) in [(1, 0, 0), (16, 0, 0), (1, 10, 30), (16, 10, 30)] {
            for seeds in [1, 3] {
                for seed in 0..trials {
                    for policy in [RoutingPolicy::Diverse, RoutingPolicy::Unrestricted] {
                        trial(
                            Topology {
                                count,
                                cluster,
                                loss,
                                churn,
                                join_rounds,
                            },
                            seeds,
                            seed,
                            policy,
                        );
                    }
                }
            }
        }
    }
}
