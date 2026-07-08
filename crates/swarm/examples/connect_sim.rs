//! Watch two NATed peers connect by id, coordinated over the DHT.
//!
//! Run with: `cargo run -p swarm --example connect_sim`

use swarm::dht::{ConnectOutcome, Event};
use swarm::sim::{NatKind, Sim};

fn backbone(n: usize, seed: u64) -> Sim {
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

fn join(sim: &mut Sim, nat: NatKind) -> usize {
    let id = sim.rng().node_id();
    let (idx, _) = sim.add_node(id);
    sim.set_nat(idx, nat);
    let boot = sim.contact(0);
    sim.dht_mut(idx).add_contact(boot);
    sim.bootstrap(idx);
    sim.run(100_000);
    idx
}

fn main() {
    println!("A 12-node Open backbone acts as DHT routers and coordinators.");
    println!("A server announces under its id; a client connects to it by id.\n");

    let pairs = [
        (NatKind::Consistent, NatKind::Consistent),
        (NatKind::Random, NatKind::Consistent),
        (NatKind::Consistent, NatKind::Random),
        (NatKind::Open, NatKind::Random),
        (NatKind::Random, NatKind::Random),
    ];

    for (client_nat, server_nat) in pairs {
        let mut sim = backbone(12, 0x99);
        let server = join(&mut sim, server_nat);
        let server_id = sim.dht(server).id();
        sim.announce(server, server_id);
        sim.run(100_000);
        sim.take_events();

        let client = join(&mut sim, client_nat);
        sim.connect(client, server_id);
        sim.run(100_000);

        let outcome = sim
            .take_events()
            .into_iter()
            .find_map(|(node, ev)| match ev {
                Event::Connected { target, outcome } if node == client && target == server_id => {
                    Some(outcome)
                }
                _ => None,
            })
            .expect("connect finished");

        let note = match outcome {
            ConnectOutcome::Direct => "dialed directly",
            ConnectOutcome::Punched => "hole punched (birthday)",
            ConnectOutcome::Relayed => "via coordinator relay",
            ConnectOutcome::NotFound => "not found",
            ConnectOutcome::TimedOut => "timed out",
        };
        println!("  client {client_nat:?} -> server {server_nat:?}  =>  {outcome:?} ({note})");
    }

    println!("\nDiscovery, coordinator signaling, and the punch decision all ran");
    println!("as real DHT messages — no central server anywhere in the path.");
}
