//! End-to-end: discover and connect to a peer by id, coordinated over the DHT.
//!
//! A server announces itself under its own id; a client looks it up, then a
//! coordinator node (one that holds the server's announce record) brokers the
//! address/NAT-type exchange, and the resulting connection type is determined by
//! the two peers' NAT types — verified for every NAT pairing, with discovery and
//! signaling flowing as real DHT messages through the simulator.

use swarm::dht::{ConnectOutcome, Event};
use swarm::sim::{NatKind, Sim};

/// Build a connected all-Open backbone of `n` nodes (the persistent routers that
/// also serve as coordinators).
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

/// Join a new peer to the network behind the given NAT, returning its index.
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

#[test]
fn announce_then_lookup_discovers_the_peer() {
    let mut sim = backbone(12, 0xA0);
    let server = join(&mut sim, NatKind::Consistent);
    let server_id = sim.dht(server).id();

    // Server announces under its own id.
    sim.announce(server, server_id);
    sim.run(100_000);
    sim.take_events();

    // A different node looks it up and should find the server in the records.
    let client = join(&mut sim, NatKind::Consistent);
    sim.lookup(client, server_id);
    sim.run(100_000);

    let peers = sim
        .take_events()
        .into_iter()
        .find_map(|(node, ev)| match ev {
            Event::LookupFinished { topic, peers } if node == client && topic == server_id => {
                Some(peers)
            }
            _ => None,
        })
        .expect("lookup should finish");
    assert!(
        peers.iter().any(|c| c.id == server_id),
        "lookup did not discover the announced server"
    );
}

/// Connect `client_nat` -> `server_nat` over the DHT and return the outcome.
fn connect_outcome(client_nat: NatKind, server_nat: NatKind, seed: u64) -> ConnectOutcome {
    let mut sim = backbone(12, seed);

    let server = join(&mut sim, server_nat);
    let server_id = sim.dht(server).id();
    sim.announce(server, server_id);
    sim.run(100_000);
    sim.take_events();

    let client = join(&mut sim, client_nat);
    sim.connect(client, server_id);
    sim.run(100_000);

    sim.take_events()
        .into_iter()
        .find_map(|(node, ev)| match ev {
            Event::Connected {
                target, outcome, ..
            } if node == client && target == server_id => Some(outcome),
            _ => None,
        })
        .expect("connect should finish")
}

#[test]
fn connect_outcomes_match_nat_pairing() {
    use ConnectOutcome::{Direct, Punched, Relayed};
    use NatKind::{Consistent, Open, Random};

    let cases = [
        (Open, Open, Direct),
        (Open, Consistent, Direct),
        (Consistent, Open, Direct),
        (Consistent, Consistent, Direct),
        (Consistent, Random, Punched),
        (Random, Consistent, Punched),
        (Open, Random, Direct),
        (Random, Open, Direct),
        (Random, Random, Relayed),
    ];

    for (i, (client, server, expected)) in cases.into_iter().enumerate() {
        let got = connect_outcome(client, server, 0xC000 + i as u64);
        assert_eq!(
            got, expected,
            "client {client:?} -> server {server:?}: expected {expected:?}, got {got:?}"
        );
    }
}

#[test]
fn connect_times_out_when_signaling_cannot_complete() {
    // Server announces, then goes offline. The client still discovers a
    // coordinator (which holds the record), signals it, but the forward to the
    // now-unreachable server is dropped — so the connect must fail with TimedOut
    // rather than hang forever.
    let mut sim = backbone(12, 0xF00D);
    let server = join(&mut sim, NatKind::Consistent);
    let server_id = sim.dht(server).id();
    sim.announce(server, server_id);
    sim.run(100_000);
    sim.take_events();

    sim.disable_node(server);

    let client = join(&mut sim, NatKind::Consistent);
    sim.connect(client, server_id);
    sim.run(1_000_000);

    let outcome = sim
        .take_events()
        .into_iter()
        .find_map(|(node, ev)| match ev {
            Event::Connected {
                target, outcome, ..
            } if node == client && target == server_id => Some(outcome),
            _ => None,
        })
        .expect("connect should resolve (to TimedOut), never hang");
    assert_eq!(outcome, ConnectOutcome::TimedOut);
}

#[test]
fn connecting_to_an_unannounced_peer_reports_not_found() {
    let mut sim = backbone(12, 0xDEAD);
    let client = join(&mut sim, NatKind::Consistent);
    // A random id that nobody announced.
    let ghost = sim.rng().node_id();

    sim.connect(client, ghost);
    sim.run(100_000);

    let outcome = sim
        .take_events()
        .into_iter()
        .find_map(|(node, ev)| match ev {
            Event::Connected {
                target, outcome, ..
            } if node == client && target == ghost => Some(outcome),
            _ => None,
        })
        .expect("connect should finish even when the target is missing");
    assert_eq!(outcome, ConnectOutcome::NotFound);
}

#[test]
fn connect_exchanges_data_addresses_both_ways() {
    // The signaling must carry each peer's data-socket address to the other: the
    // initiator learns the target's (to punch to), and the target learns the
    // initiator's (to accept from). In the sim a node advertises its own DHT
    // address as its data address (there are no separate data sockets).
    let mut sim = backbone(12, 0x0DA7A);
    let server = join(&mut sim, NatKind::Consistent);
    let server_id = sim.dht(server).id();
    sim.announce(server, server_id);
    sim.run(100_000);
    sim.take_events();

    let client = join(&mut sim, NatKind::Consistent);
    let client_id = sim.dht(client).id();
    let client_addr = sim.addr(client);
    let server_addr = sim.addr(server);

    sim.connect(client, server_id);
    sim.run(100_000);
    let events = sim.take_events();

    // Initiator side: `Connected` carries the target's data address to punch to.
    let peer_data_addr = events
        .iter()
        .find_map(|(node, ev)| match ev {
            Event::Connected {
                target,
                peer_data_addr,
                ..
            } if *node == client && *target == server_id => Some(*peer_data_addr),
            _ => None,
        })
        .expect("client should report Connected");
    assert_eq!(
        peer_data_addr,
        Some(server_addr),
        "initiator should learn the target's data address"
    );

    // Target side: `IncomingConnect` carries the initiator's id and data address.
    let (inc_initiator, inc_data) = events
        .iter()
        .find_map(|(node, ev)| match ev {
            Event::IncomingConnect {
                initiator,
                initiator_data_addr,
                ..
            } if *node == server => Some((*initiator, *initiator_data_addr)),
            _ => None,
        })
        .expect("server should report IncomingConnect");
    assert_eq!(inc_initiator, client_id, "target learns the initiator's id");
    assert_eq!(
        inc_data, client_addr,
        "target learns the initiator's data address"
    );
}
