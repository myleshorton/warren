//! Watch a DHT bootstrap itself and answer a lookup.
//!
//! Run with: `cargo run -p swarm --example dht_sim`

use swarm::dht::Event;
use swarm::sim::Sim;

fn main() {
    let n = 30;
    let mut sim = Sim::new(10, 0xDECAF);

    let id0 = sim.rng().node_id();
    sim.add_node(id0);
    println!("Bootstrapping a {n}-node DHT (10ms virtual latency)\n");

    let mut total_steps = 0;
    for i in 1..n {
        let id = sim.rng().node_id();
        let (idx, _) = sim.add_node(id);
        let boot = sim.contact(0);
        sim.dht_mut(idx).add_contact(boot);
        sim.bootstrap(idx);
        total_steps += sim.run(100_000);
        sim.take_events();
        if i % 5 == 0 || i == n - 1 {
            let known: usize = (0..=i).map(|k| sim.dht(k).routing_len()).sum();
            println!(
                "  joined {:2} nodes  |  virtual time {:>5}ms  |  contacts known across network: {known}",
                i + 1,
                sim.now()
            );
        }
    }
    println!("\nbootstrap simulation cost: {total_steps} scheduler steps");

    println!("\nRouting tables after bootstrap:");
    for i in 0..n {
        println!("  node {i:2} knows {} peers", sim.dht(i).routing_len());
    }

    // Look up node 29's id starting from node 3 and show the path found.
    let target = sim.dht(n - 1).id();
    println!("\nNode 3 looks up node {}'s id {target:?}", n - 1);
    let q = sim.find_node(3, target);
    sim.run(100_000);

    if let Some((_, Event::QueryFinished { closest, .. })) =
        sim.take_events().into_iter().find(|(node, ev)| {
            *node == 3 && matches!(ev, Event::QueryFinished { query, .. } if *query == q)
        })
    {
        println!(
            "  found {} closest nodes; nearest is {:?}",
            closest.len(),
            closest[0].id
        );
        let oracle = sim.brute_force_closest(&target, 3);
        println!("  brute-force closest: {oracle:?}");
        println!(
            "  match: {}",
            if closest[0].id == oracle {
                "YES ✓"
            } else {
                "NO ✗"
            }
        );
    }
}
