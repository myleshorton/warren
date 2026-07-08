//! Integration tests over real UDP sockets on loopback.
//!
//! Unlike the swarm crate's deterministic simulator, these bind actual
//! `tokio::net::UdpSocket`s and exercise the full driver: bootstrap, announce,
//! lookup, and DHT-coordinated connect — proving the sans-IO core works
//! unchanged over the network. (On loopback every node is directly reachable,
//! so a coordinated connect resolves to `Direct`.)

use std::time::Duration;

use driver::Node;
use swarm::dht::ConnectOutcome;
use swarm::sim::Rng;
use tokio::time::timeout;

const LO: &str = "127.0.0.1:0";
const T: Duration = Duration::from_secs(5);

/// Bring up a `boot` node plus `n` bootstrapped peers, all on loopback.
async fn network(n: usize, seed: u64) -> (Node, Vec<Node>) {
    let lo = LO.parse().unwrap();
    let mut rng = Rng::new(seed);
    let boot = Node::bind(lo, rng.node_id()).await.unwrap();

    let mut peers = Vec::new();
    for _ in 0..n {
        let node = Node::bind(lo, rng.node_id()).await.unwrap();
        node.add_contact(boot.contact()).await.unwrap();
        timeout(T, node.bootstrap())
            .await
            .expect("bootstrap should settle")
            .expect("node alive");
        peers.push(node);
    }
    (boot, peers)
}

#[tokio::test]
async fn announce_then_lookup_over_udp() {
    let (_boot, peers) = network(6, 0xA1).await;
    let server = &peers[0];
    let client = &peers[1];

    timeout(T, server.announce(server.id()))
        .await
        .expect("announce should complete")
        .expect("node alive");

    let found = timeout(T, client.lookup(server.id()))
        .await
        .expect("lookup should complete")
        .expect("node alive");
    assert!(
        found.iter().any(|c| c.id == server.id()),
        "lookup over UDP should discover the announced server"
    );
}

#[tokio::test]
async fn connect_by_id_over_udp() {
    let (_boot, peers) = network(6, 0xB2).await;
    let server = &peers[0];
    let client = &peers[1];

    timeout(T, server.announce(server.id()))
        .await
        .expect("announce should complete")
        .expect("node alive");

    let outcome = timeout(T, client.connect(server.id()))
        .await
        .expect("connect should complete")
        .expect("node alive");
    // Every node is directly reachable on loopback, so the coordinated connect
    // is a direct dial.
    assert_eq!(outcome, ConnectOutcome::Direct);
}

#[tokio::test]
async fn connect_to_unannounced_peer_is_not_found() {
    let (_boot, peers) = network(4, 0xC3).await;
    let client = &peers[0];
    let ghost = Rng::new(0xDEAD).node_id();

    let outcome = timeout(T, client.connect(ghost))
        .await
        .expect("connect should resolve, not hang")
        .expect("node alive");
    assert_eq!(outcome, ConnectOutcome::NotFound);
}

#[tokio::test]
async fn concurrent_connects_to_same_target_all_resolve() {
    // Two callers connecting to the same target must both get a result — the
    // driver joins them to one operation rather than clobbering a waiter.
    let (_boot, peers) = network(6, 0xD4).await;
    let server = &peers[0];
    let client = &peers[1];
    timeout(T, server.announce(server.id()))
        .await
        .expect("announce")
        .expect("node alive");

    let (a, b) = timeout(T, async {
        tokio::join!(client.connect(server.id()), client.connect(server.id()))
    })
    .await
    .expect("both connects should resolve, not hang");
    assert_eq!(a.expect("node alive"), ConnectOutcome::Direct);
    assert_eq!(b.expect("node alive"), ConnectOutcome::Direct);
}
