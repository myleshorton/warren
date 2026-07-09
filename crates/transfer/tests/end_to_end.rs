//! The whole stack in one test: a viewer discovers a publisher by key over the
//! DHT, punches a channel to it, and streams a signed feed across it — verifying
//! every block — with no server in the path.
//!
//! The feed's public key doubles as the publisher's DHT node id (as in
//! Hypercore), so one key is both "what to verify against" and "who to reach".

use std::sync::Arc;
use std::time::Duration;

use crypto::Keypair;
use driver::{ConnectOutcome, Node};
use feed::Log;
use swarm::sim::Rng;
use swarm::NodeId;
use tokio::time::timeout;
use transfer::{download_feed, serve_feed, Config};

const LO: &str = "127.0.0.1:0";
const T: Duration = Duration::from_secs(20);

/// A `boot` node plus `n` bootstrapped peers on loopback.
async fn network(n: usize, seed: u64) -> (Node, Vec<Node>) {
    let lo = LO.parse().unwrap();
    let mut rng = Rng::new(seed);
    let boot = Node::bind(lo, rng.node_id()).await.unwrap();
    let mut peers = Vec::new();
    for _ in 0..n {
        let node = Node::bind(lo, rng.node_id()).await.unwrap();
        node.add_contact(boot.contact()).await.unwrap();
        timeout(T, node.bootstrap()).await.unwrap().unwrap();
        peers.push(node);
    }
    (boot, peers)
}

#[tokio::test]
async fn discover_connect_and_stream_a_feed() {
    let (_boot, peers) = network(6, 0x5EED).await;
    let bootstrap = peers[0].contact();

    // Publisher: a signed feed whose public key is also its DHT node id.
    let feed_kp = Keypair::from_seed(&[42u8; 32]);
    let feed_pk = feed_kp.public();
    let node_id = NodeId::from_bytes(feed_pk.to_bytes());
    let frames: Vec<Vec<u8>> = (0..12).map(|i| format!("frame {i}").into_bytes()).collect();
    let mut log = Log::new(feed_kp);
    for frame in &frames {
        log.append(frame.clone());
    }
    let log = Arc::new(log);

    let publisher = Node::bind(LO.parse().unwrap(), node_id).await.unwrap();
    publisher.add_contact(bootstrap).await.unwrap();
    timeout(T, publisher.bootstrap()).await.unwrap().unwrap();
    timeout(T, publisher.announce(node_id))
        .await
        .unwrap()
        .unwrap();

    // Serve one inbound pull.
    let serve_log = log.clone();
    let serve_node = publisher.clone();
    tokio::spawn(async move {
        if let Ok(mut channel) = serve_node.next_incoming().await {
            let _ = serve_feed(&mut channel, &serve_log, &Config::default()).await;
        }
    });

    // Viewer: knows only the feed key. Discover + connect + stream.
    let viewer = Node::bind(LO.parse().unwrap(), Rng::new(0xF00).node_id())
        .await
        .unwrap();
    viewer.add_contact(bootstrap).await.unwrap();
    timeout(T, viewer.bootstrap()).await.unwrap().unwrap();

    let conn = timeout(T, viewer.connect(node_id))
        .await
        .unwrap()
        .expect("connect");
    assert_eq!(conn.outcome, ConnectOutcome::Direct);
    let mut channel = conn.channel.expect("a direct connect yields a channel");

    let received = timeout(T, download_feed(&mut channel, feed_pk, &Config::default()))
        .await
        .expect("download finishes")
        .expect("download verifies");
    assert_eq!(received, frames);
}
