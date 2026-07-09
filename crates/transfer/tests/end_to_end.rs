//! The whole stack in one test: a viewer discovers a publisher over the DHT by a
//! *blinded, rotating topic* derived from the feed key and the current epoch,
//! punches a channel to it, and streams a signed feed across it — verifying
//! every block — with no server in the path.
//!
//! Discovery is both decoupled and blinded:
//!  * the publisher's DHT node id is random, independent of the feed key, so the
//!    key is not a node id — dialing the cleartext key (`connect(feed_key)`)
//!    reaches no one (PR #22);
//!  * content is announced under `blinded_topic(feed_key, epoch)`, not the
//!    cleartext key, so a DHT crawler who does not hold the feed key sees only an
//!    opaque id that rotates each epoch — it cannot map the topic to the content
//!    or keep a static blocklist. A viewer who knows the key computes the same
//!    topic.
//!
//! Epoch boundaries are covered by *overlap*: the publisher announces the
//! current *and* next epoch, a viewer looks up the current *and* previous — so a
//! clock that has ticked over still finds the provider. Both the steady state
//! and the boundary are exercised.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crypto::{Keypair, PublicKey};
use driver::{ConnectOutcome, Node};
use feed::Log;
use swarm::sim::Rng;
use swarm::{Contact, NodeId};
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

/// The blinded topic for `epoch` as a DHT key.
fn topic(feed_pk: &PublicKey, epoch: u64) -> NodeId {
    NodeId::from_bytes(feed_pk.blinded_topic(epoch))
}

/// Bring up a publisher that serves a small signed feed. It announces its random
/// node id (reachability, so a coordinated connect can reach it) and the content
/// under each of `epochs`' blinded topics. Returns the node, its id, the feed key
/// (the content id / verification key), and the frames it serves.
async fn publish(
    bootstrap: Contact,
    node_seed: u64,
    epochs: &[u64],
) -> (Node, NodeId, PublicKey, Vec<Vec<u8>>) {
    let feed_kp = Keypair::from_seed(&[42u8; 32]);
    let feed_pk = feed_kp.public();
    let node_id = Rng::new(node_seed).node_id();
    assert_ne!(
        node_id.as_bytes(),
        &feed_pk.to_bytes(),
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
    timeout(T, publisher.announce(node_id))
        .await
        .unwrap()
        .unwrap();
    for &e in epochs {
        timeout(T, publisher.announce(topic(&feed_pk, e)))
            .await
            .unwrap()
            .unwrap();
    }

    let serve_log = log.clone();
    let serve_node = publisher.clone();
    tokio::spawn(async move {
        if let Ok(mut channel) = serve_node.next_incoming().await {
            let _ = serve_feed(&mut channel, &serve_log, &Config::default()).await;
        }
    });

    (publisher, node_id, feed_pk, frames)
}

/// Look content up under any of `topics`, merged and de-duplicated by node id —
/// the viewer-side boundary overlap (current + previous epoch).
async fn discover(node: &Node, topics: &[NodeId]) -> Vec<Contact> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for t in topics {
        for c in timeout(T, node.lookup(*t)).await.unwrap().unwrap() {
            if seen.insert(c.id) {
                out.push(c);
            }
        }
    }
    out
}

/// Connect to `provider` and stream the feed, checking it verifies to `frames`.
async fn fetch_and_verify(viewer: &Node, provider: NodeId, feed_pk: PublicKey, frames: &[Vec<u8>]) {
    let conn = timeout(T, viewer.connect(provider))
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

#[tokio::test]
async fn discover_by_blinded_topic_and_stream_a_feed() {
    // Keep the peers alive (they populate the DHT); bootstrap new nodes off the
    // boot node, as the other loopback tests do.
    let (boot, _peers) = network(6, 0x5EED).await;
    let bootstrap = boot.contact();

    // A fixed epoch stands in for wall-clock time; the derivation is pure, so the
    // test needs no clock. The publisher announces the current and next epoch.
    const EPOCH: u64 = 100;
    let (_publisher, node_id, feed_pk, frames) =
        publish(bootstrap, 0xDEC0DE, &[EPOCH, EPOCH + 1]).await;

    // The blinded topic is opaque — not the cleartext feed key.
    assert_ne!(topic(&feed_pk, EPOCH).as_bytes(), &feed_pk.to_bytes());

    let viewer = Node::bind(LO.parse().unwrap(), Rng::new(0xF00).node_id())
        .await
        .unwrap();
    viewer.add_contact(bootstrap).await.unwrap();
    timeout(T, viewer.bootstrap()).await.unwrap().unwrap();

    // Decoupling still holds: the cleartext feed key is neither a node id nor an
    // announced topic, so dialing it as a node reaches no one.
    let by_key = timeout(T, viewer.connect(NodeId::from_bytes(feed_pk.to_bytes())))
        .await
        .unwrap()
        .expect("connect resolves");
    assert_eq!(
        by_key.outcome,
        ConnectOutcome::NotFound,
        "the feed key must not double as a node id"
    );
    assert!(by_key.channel.is_none());

    // Discover under the current and previous epoch (viewer-side overlap), then
    // connect to the random-id provider and stream.
    let providers = discover(
        &viewer,
        &[topic(&feed_pk, EPOCH), topic(&feed_pk, EPOCH - 1)],
    )
    .await;
    let provider = providers
        .iter()
        .find(|c| c.id == node_id)
        .expect("the publisher announced the content under its blinded topic");

    fetch_and_verify(&viewer, provider.id, feed_pk, &frames).await;
}

#[tokio::test]
async fn discovery_survives_an_epoch_boundary() {
    // The publisher announced the current and next epoch (E, E+1) at some earlier
    // instant. A viewer whose clock has since ticked to E+1 looks up its current
    // and previous epoch (E+1, E). The publisher's *next*-epoch announce (E+1)
    // meets the viewer's *current* (E+1), so the boundary opens no gap — even
    // though the two disagree about which epoch "now" is.
    let (boot, _peers) = network(6, 0xB0475).await;
    let bootstrap = boot.contact();

    const E: u64 = 100;
    let (_publisher, node_id, feed_pk, frames) = publish(bootstrap, 0xACE, &[E, E + 1]).await;

    let viewer = Node::bind(LO.parse().unwrap(), Rng::new(0xBEE).node_id())
        .await
        .unwrap();
    viewer.add_contact(bootstrap).await.unwrap();
    timeout(T, viewer.bootstrap()).await.unwrap().unwrap();

    // Viewer is one epoch ahead: current = E+1, previous = E.
    let providers = discover(&viewer, &[topic(&feed_pk, E + 1), topic(&feed_pk, E)]).await;
    let provider = providers
        .iter()
        .find(|c| c.id == node_id)
        .expect("overlap should bridge the epoch boundary");

    fetch_and_verify(&viewer, provider.id, feed_pk, &frames).await;
}
