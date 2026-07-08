//! Watch a node classify its own NAT by probing the swarm.
//!
//! Run with: `cargo run -p swarm --example nat_sim`

use swarm::sim::{NatKind, Sim};

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

fn main() {
    println!("A node probes 5 peers; each echoes the address it saw. The pattern");
    println!("of observed addresses classifies the local NAT.\n");

    for kind in [NatKind::Open, NatKind::Consistent, NatKind::Random] {
        let mut sim = built_network(8, 0x77AB);
        let node = 3;
        sim.set_nat(node, kind);
        sim.sample_nat(node, 5);
        sim.run(100_000);
        println!(
            "  behind {:<11} -> {} samples -> classified {:?}",
            format!("{kind:?}"),
            sim.dht(node).nat_samples(),
            sim.dht(node).firewall().expect("classified after sampling"),
        );
    }

    println!("\nRandom shows varying observed ports (symmetric NAT); the other two");
    println!("show a stable port, split by whether unsolicited inbound is reachable.");
}
