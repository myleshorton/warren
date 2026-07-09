//! The whole stack in one test: a viewer discovers a publisher over the DHT by a
//! *content topic*, punches a channel to it, and streams a signed feed across it
//! — verifying every block — with no server in the path.
//!
//! The feed's public key is the content id and the discovery topic, but the
//! publisher's DHT node id is *independent* (random). So the key no longer
//! doubles as a node id: `connect(feed_key)` — treating the scraped key as
//! something to dial — resolves `NotFound`. Discovery instead goes through a
//! *topic* lookup, which reveals which (random-id) node serves the content.
//! (That lookup still returns the provider's contact, so decoupling the node id
//! is not the same as hiding the provider — that is what blinded topics harden.)
//! This test asserts the decoupling: connecting by the feed key finds nothing,
//! while the topic-lookup path streams and verifies the whole feed.

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
        peers.push(node);
    }
    // Bootstrap the peers concurrently: a stuck bootstrap then surfaces in ~T
    // rather than n*T, keeping CI failure feedback fast.
    let mut joins = tokio::task::JoinSet::new();
    for node in &peers {
        let node = node.clone();
        joins.spawn(async move { timeout(T, node.bootstrap()).await });
    }
    while let Some(joined) = joins.join_next().await {
        joined.unwrap().unwrap().unwrap();
    }
    (boot, peers)
}

#[tokio::test]
async fn discover_by_topic_connect_and_stream_a_feed() {
    // Keep the peers alive (they populate the DHT); bootstrap new nodes off the
    // boot node, as the other loopback tests do.
    let (boot, _peers) = network(6, 0x5EED).await;
    let bootstrap = boot.contact();

    // Publisher: a signed feed. Its public key is the content id and the DHT
    // discovery *topic* — but its node id is random and unrelated to the key.
    let feed_kp = Keypair::from_seed(&[42u8; 32]);
    let feed_pk = feed_kp.public();
    let topic = NodeId::from_bytes(feed_pk.to_bytes());
    let node_id = Rng::new(0xDEC0DE).node_id();
    assert_ne!(
        node_id, topic,
        "the publisher's node id must be independent of its feed key"
    );

    let frames: Vec<Vec<u8>> = (0..12).map(|i| format!("frame {i}").into_bytes()).collect();
    let mut log = Log::new(feed_kp);
    for frame in &frames {
        log.append(frame.clone());
    }
    let log = Arc::new(log);

    let publisher = Node::bind(LO.parse().unwrap(), node_id).await.unwrap();
    publisher.add_contact(bootstrap).await.unwrap();
    timeout(T, publisher.bootstrap()).await.unwrap().unwrap();
    // Two announces, distinct in purpose: register the (random-id) node so a
    // coordinated connect can reach it, and register the content under its topic
    // so a viewer holding only the feed key can discover who serves it.
    timeout(T, publisher.announce(node_id))
        .await
        .unwrap()
        .unwrap();
    timeout(T, publisher.announce(topic))
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

    // Viewer: knows only the feed key.
    let viewer = Node::bind(LO.parse().unwrap(), Rng::new(0xF00).node_id())
        .await
        .unwrap();
    viewer.add_contact(bootstrap).await.unwrap();
    timeout(T, viewer.bootstrap()).await.unwrap().unwrap();

    // Decoupling, proven: connecting *by the feed key as a node id* — what a
    // censor who scraped the key would try — reaches no one, because no node
    // self-announces under the feed key. The content record living near that key
    // belongs to a random-id node, so it is not a coordinator for a connect-by-id.
    let by_key = timeout(T, viewer.connect(topic))
        .await
        .unwrap()
        .expect("connect resolves");
    assert_eq!(
        by_key.outcome,
        ConnectOutcome::NotFound,
        "the feed key must not double as a node locator"
    );
    assert!(by_key.channel.is_none());

    // The real path: look the topic up to learn which node serves it, then
    // connect to that node by its (random) id.
    let providers = timeout(T, viewer.lookup(topic)).await.unwrap().unwrap();
    let provider = providers
        .iter()
        .find(|c| c.id == node_id)
        .expect("the publisher announced the content under its topic");

    let conn = timeout(T, viewer.connect(provider.id))
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
