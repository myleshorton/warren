//! End-to-end NAT self-classification through the DHT's own ping traffic.
//!
//! A node pings several peers; each echoes back the source address it saw. Those
//! observations drive classification. Verified in the simulator's minimal NAT
//! model: a node behind each NAT kind reaches the right verdict, and none is
//! reached before enough samples arrive.

use swarm::sim::{NatKind, Sim};
use swarm::Firewall;

/// Build a connected all-Open network so every node has peers to probe.
fn built_network(n: usize, seed: u64) -> Sim {
    let mut sim = Sim::new(10, seed);
    let id0 = sim.rng().node_id();
    sim.add_node(id0);
    for _ in 1..n {
        let id = sim.rng().node_id();
        let (idx, _) = sim.add_node(id);
        let boot = sim.contact(0);
        sim.dht_mut(idx).add_contact(boot);
        sim.bootstrap(idx);
        sim.run(100_000);
    }
    sim
}

fn classify(nat: NatKind, seed: u64) -> Option<Firewall> {
    let mut sim = built_network(8, seed);
    let node = 3;
    sim.set_nat(node, nat);
    sim.sample_nat(node, 5);
    sim.run(100_000);
    sim.dht(node).firewall()
}

#[test]
fn undecided_before_sampling() {
    let sim = built_network(8, 1);
    assert_eq!(sim.dht(3).firewall(), None);
    assert_eq!(sim.dht(3).nat_samples(), 0);
}

#[test]
fn open_node_classifies_open() {
    assert_eq!(classify(NatKind::Open, 2), Some(Firewall::Open));
}

#[test]
fn consistent_node_classifies_consistent() {
    assert_eq!(classify(NatKind::Consistent, 3), Some(Firewall::Consistent));
}

#[test]
fn random_node_classifies_random() {
    assert_eq!(classify(NatKind::Random, 4), Some(Firewall::Random));
}

#[test]
fn collects_samples_from_multiple_peers() {
    let mut sim = built_network(8, 5);
    sim.sample_nat(3, 5);
    sim.run(100_000);
    // Every probed peer replied, so we gathered the full sample set.
    assert_eq!(sim.dht(3).nat_samples(), 5);
}
