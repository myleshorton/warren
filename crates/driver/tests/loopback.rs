//! Integration tests over real UDP sockets on loopback.
//!
//! Unlike the swarm crate's deterministic simulator, these bind actual
//! `tokio::net::UdpSocket`s and exercise the full driver: bootstrap, announce,
//! lookup, and DHT-coordinated connect — proving the sans-IO core works
//! unchanged over the network. (On loopback every node is directly reachable,
//! so a coordinated connect resolves to `Direct`.)

use std::time::Duration;

use driver::{ConnectError, Node};
use swarm::dht::ConnectOutcome;
use swarm::sim::Rng;
use tokio::time::timeout;

const LO: &str = "127.0.0.1:0";
const T: Duration = Duration::from_secs(5);

/// Bring up a `boot` node plus `n` bootstrapped peers, all on loopback.
async fn network(n: usize, seed: u64) -> (Node, Vec<Node>) {
    let lo = LO.parse().unwrap();
    let mut rng = Rng::new(seed);
    let boot = Node::bind(lo, rng.keypair()).await.unwrap();

    let mut peers = Vec::new();
    for _ in 0..n {
        let node = Node::bind(lo, rng.keypair()).await.unwrap();
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

    let conn = timeout(T, client.connect(server.id()))
        .await
        .expect("connect should complete")
        .expect("connect succeeds");
    // Every node is directly reachable on loopback, so the coordinated connect
    // is a direct dial — and it yields a live channel, punched end to end.
    assert_eq!(conn.outcome, ConnectOutcome::Direct);
    assert!(
        conn.channel.is_some(),
        "a direct connect should yield a channel"
    );
}

#[tokio::test]
async fn connect_to_unannounced_peer_is_not_found() {
    let (_boot, peers) = network(4, 0xC3).await;
    let client = &peers[0];
    let ghost = Rng::new(0xDEAD).node_id();

    let conn = timeout(T, client.connect(ghost))
        .await
        .expect("connect should resolve, not hang")
        .expect("connect succeeds");
    assert_eq!(conn.outcome, ConnectOutcome::NotFound);
    assert!(conn.channel.is_none(), "a not-found connect has no channel");
}

#[tokio::test]
async fn concurrent_connects_to_distinct_targets_each_get_a_channel() {
    // One client connecting to two different servers at once: each connect binds
    // its own data socket and punches independently, so both yield a channel.
    let (_boot, peers) = network(8, 0xD4).await;
    let client = &peers[0];
    let (s1, s2) = (&peers[1], &peers[2]);
    for s in [s1, s2] {
        timeout(T, s.announce(s.id()))
            .await
            .expect("announce")
            .expect("node alive");
    }

    let (a, b) = timeout(T, async {
        tokio::join!(client.connect(s1.id()), client.connect(s2.id()))
    })
    .await
    .expect("both connects should resolve, not hang");
    let a = a.expect("connect a succeeds");
    let b = b.expect("connect b succeeds");
    assert_eq!(a.outcome, ConnectOutcome::Direct);
    assert_eq!(b.outcome, ConnectOutcome::Direct);
    assert!(
        a.channel.is_some() && b.channel.is_some(),
        "each concurrent connect should yield its own channel"
    );
}

#[tokio::test]
async fn second_concurrent_connect_to_same_target_is_in_progress() {
    // Only one connect per target at a time. Two fired at once resolve to exactly
    // one success and one `InProgress`: the second is rejected without disrupting
    // the first (and is NOT misreported as the node having shut down).
    let (_boot, peers) = network(6, 0xE5).await;
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

    let results = [a, b];
    let ok = results.iter().filter(|r| r.is_ok()).count();
    let in_progress = results
        .iter()
        .filter(|r| matches!(r, Err(ConnectError::InProgress)))
        .count();
    assert_eq!(ok, 1, "exactly one connect should succeed, got {results:?}");
    assert_eq!(
        in_progress, 1,
        "the other should be rejected as InProgress, got {results:?}"
    );
}
