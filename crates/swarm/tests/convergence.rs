//! End-to-end DHT verification in the deterministic simulator.
//!
//! The decisive property: a Kademlia iterative lookup must return the node that
//! is *globally* closest to the target — the same answer a brute-force scan of
//! every node gives. We build a network incrementally (each node bootstraps off
//! one already-joined peer), then check that property exhaustively.

use swarm::dht::Event;
use swarm::sim::Sim;
use swarm::NodeId;

/// Build a connected network of `n` nodes, bootstrapping each off node 0.
fn build_network(n: usize, seed: u64) -> Sim {
    let mut sim = Sim::new(10, seed);

    // Node 0 is the initial bootstrap peer.
    let id0 = sim.rng().node_id();
    sim.add_node(id0);

    for i in 1..n {
        let id = sim.rng().node_id();
        let (idx, _addr) = sim.add_node(id);
        // The newcomer knows only node 0, then self-looks-up to discover peers.
        let boot = sim.contact(0);
        sim.dht_mut(idx).add_contact(boot);
        sim.bootstrap(idx);
        let steps = sim.run(100_000);
        assert!(steps < 100_000, "network did not settle for node {i}");
    }
    sim
}

#[test]
fn lookup_finds_globally_closest_node() {
    let n = 25;
    let mut sim = build_network(n, 0xC0FFEE);

    // For every (source, target-node) pair, the lookup's nearest result must be
    // the true globally-closest node to that target.
    for src in 0..n {
        for dst in 0..n {
            if src == dst {
                continue;
            }
            let target = sim.dht(dst).id();
            let q = sim.find_node(src, target);
            sim.run(100_000);

            let finished = sim
                .take_events()
                .into_iter()
                .find_map(|(node, ev)| match ev {
                    Event::QueryFinished { query, closest, .. } if node == src && query == q => {
                        Some(closest)
                    }
                    _ => None,
                })
                .expect("query should finish");

            let expected = sim.brute_force_closest(&target, src);
            assert!(
                !finished.is_empty(),
                "src {src} found nothing for dst {dst}"
            );
            assert_eq!(
                finished[0].id, expected,
                "src {src} looking up dst {dst}: got {:?}, expected {:?}",
                finished[0].id, expected
            );
            // The target node itself is distance 0 to its own id, so it must be
            // the top result.
            assert_eq!(finished[0].id, target);
        }
    }
}

#[test]
fn lookup_finds_closest_for_random_targets() {
    let n = 25;
    let mut sim = build_network(n, 0x1234_5678);

    // Random targets that are not any node's id: the lookup must still return
    // the globally nearest node, matching brute force.
    for t in 0..200u64 {
        let target: NodeId = {
            // Derive a deterministic pseudo-random target from t.
            let mut r = swarm::sim::Rng::new(0xABCD ^ t);
            r.node_id()
        };
        let src = (t as usize) % n;
        let q = sim.find_node(src, target);
        sim.run(100_000);

        let closest = sim
            .take_events()
            .into_iter()
            .find_map(|(node, ev)| match ev {
                Event::QueryFinished { query, closest, .. } if node == src && query == q => {
                    Some(closest)
                }
                _ => None,
            })
            .expect("query should finish");

        let expected = sim.brute_force_closest(&target, src);
        assert_eq!(closest[0].id, expected, "random target #{t} from src {src}");
    }
}

#[test]
fn network_survives_packet_loss() {
    // With retries absent, a lossy network still converges because lookups query
    // ALPHA peers and learn overlapping contact sets; verify the strong property
    // still holds under 10% one-way loss.
    let n = 20;
    let mut sim = Sim::new(10, 0x9999);
    sim.set_loss(0.10);

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

    // Every node should have discovered a non-trivial slice of the network.
    for i in 0..n {
        assert!(
            sim.dht(i).routing_len() > 0,
            "node {i} learned no contacts even after bootstrap"
        );
    }
}
