//! Blind-mirror store-and-forward, end to end over a real DHT backbone.
//!
//! The Layer-2 promise: a feed stays **discoverable and live-tailable even after its
//! author goes offline**, because a mirror keeps a verified replica and serves it.
//! This test proves it with real [`driver::Node`]s on loopback — no shortcut, no
//! in-memory `Link`:
//!
//!  1. an author publishes a feed and announces itself under the feed topic;
//!  2. a mirror bootstraps a **verified** [`feed::Replica`] of it (a doctored feed
//!     could not build one) via [`Session::mirror_feed`] and starts serving it;
//!  3. the author goes **offline** (its node is dropped, its accept loop aborted);
//!  4. a fresh subscriber calls [`Session::subscribe`], which finds the feed's
//!     providers over the DHT and — the author being gone — **fails over to the
//!     mirror**, receiving every block, each verified against the author's key.
//!
//! Trust flows from the author's feed key alone: the mirror is never trusted, and a
//! subscriber that reaches only the mirror still gets a faithful, tamper-evident
//! copy of the author's feed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use crypto::{Keypair, PublicKey};
use driver::Node;
use swarm::{Contact, NodeId};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{timeout, Instant};
use warren::session::{Keys, Session};

const LO: &str = "127.0.0.1:0";
const T: Duration = Duration::from_secs(20);

/// A `boot` node plus `n` bootstrapped peers on loopback — a live DHT the sessions
/// announce into and look up over.
async fn network(n: usize) -> (Node, Vec<Node>) {
    let lo = LO.parse().unwrap();
    let boot = Node::bind(lo, id(0)).await.unwrap();
    let mut peers = Vec::new();
    for i in 0..n {
        let node = Node::bind(lo, id(100 + i as u8)).await.unwrap();
        node.add_contact(boot.contact()).await.unwrap();
        timeout(T, node.bootstrap()).await.unwrap().unwrap();
        peers.push(node);
    }
    (boot, peers)
}

/// A distinct, fixed node id (the DHT id is decoupled from any feed key).
fn id(n: u8) -> NodeId {
    let mut b = [0u8; 32];
    b[0] = n;
    b[1] = n.wrapping_mul(31).wrapping_add(7);
    NodeId::from_bytes(b)
}

/// Bind a bootstrapped node with the given id.
async fn joined(bootstrap: Contact, node_id: NodeId) -> Node {
    let node = Node::bind(LO.parse().unwrap(), node_id).await.unwrap();
    node.add_contact(bootstrap).await.unwrap();
    timeout(T, node.bootstrap()).await.unwrap().unwrap();
    node
}

/// Build a session over `node` with a fresh empty feed keyed by `feed_seed`. All
/// sessions share the same key domains, so they derive the same feed topic for a
/// given author key (what lets a subscriber find every provider of a feed).
fn make_session(node: Node, feed_seed: [u8; 32]) -> (Session, PublicKey) {
    let kp = Keypair::from_seed(&feed_seed);
    let pk = kp.public();
    let keys = Keys {
        channel_psk: b"backbone-psk".to_vec(),
        content_key: b"backbone-content-key".to_vec(),
        channel_domain: b"warren-test:channel".to_vec(),
        content_domain: b"warren-test:content".to_vec(),
        feed_domain: b"warren-test:feed".to_vec(),
        kek_domain: b"warren-test:kek".to_vec(),
    };
    let session = Session::new(
        node,
        Arc::new(StdMutex::new(feed::Log::new(kp))),
        Arc::new(AsyncMutex::new(blob::Store::new())),
        pk,
        keys,
        std::env::temp_dir(),
        Arc::new(StdMutex::new(Vec::new())),
        Arc::new(StdMutex::new(HashMap::new())),
    );
    (session, pk)
}

/// Run an accept loop that answers feed-by-key requests via [`Session::serve_by_key`]
/// — exactly what Murmur's accept loop dispatches on `REQ_FEED_KEY`. Returns the
/// task handle so the caller can `abort()` it to take the node's feed service down.
fn spawn_serve_by_key(session: Session) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(mut ch) = session.node.next_incoming().await {
            let s = session.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let Ok(n) = ch.recv(&mut buf).await else {
                    return;
                };
                if n >= 33 && buf[0] == warren::protocol::REQ_FEED_KEY {
                    if let Ok(pk) = <[u8; 32]>::try_from(&buf[1..33]) {
                        if let Ok(key) = crypto::PublicKey::from_bytes(&pk) {
                            s.serve_by_key(&mut ch, key, &transfer::Config::default())
                                .await;
                        }
                    }
                }
            });
        }
    })
}

#[tokio::test]
async fn a_mirror_keeps_a_feed_tailable_after_its_author_goes_offline() {
    let (boot, _peers) = network(4).await;
    let bootstrap = boot.contact();

    // --- Author: a 5-block feed, announced under its feed topic, served by key. ---
    let (author, author_key) = make_session(joined(bootstrap, id(1)).await, [0xAA; 32]);
    {
        let log = author.log();
        let mut g = log.lock().expect("log");
        for i in 0..5 {
            g.append(format!("msg {i}").into_bytes());
        }
    }
    let author_id = author.node.id();
    // Announce the node id (so a provider can be `connect`ed to) and the feed topic
    // (so it's discoverable as a provider of this feed) — what Murmur's announce loop
    // does every round.
    timeout(T, author.node.announce(author_id))
        .await
        .unwrap()
        .unwrap();
    timeout(T, author.node.announce(author.own_feed_topic()))
        .await
        .unwrap()
        .unwrap();
    let author_serve = spawn_serve_by_key(author.clone());

    // --- Mirror: bootstrap a verified replica of the author's feed, then serve it.
    // mirror_feed also announces the mirror under the feed topic. ---
    let (mirror, _mirror_key) = make_session(joined(bootstrap, id(2)).await, [0xBB; 32]);
    let mirror_id = mirror.node.id();
    timeout(T, mirror.node.announce(mirror_id))
        .await
        .unwrap()
        .unwrap();
    let (replica, _appended) = timeout(T, mirror.mirror_feed(author_id, author_key))
        .await
        .unwrap()
        .expect("mirror bootstraps a replica from the author");
    assert_eq!(
        replica.lock().expect("replica").len(),
        5,
        "the mirror holds a faithful, complete copy of the author's feed"
    );
    let _mirror_serve = spawn_serve_by_key(mirror.clone());

    // --- The author goes offline: stop serving and drop its node. ---
    author_serve.abort();
    drop(author);

    // --- Subscriber: tail the author's feed by key. The author is gone, so the DHT
    // failover in Session::subscribe must fall through to the mirror. ---
    let subscriber = make_session(joined(bootstrap, id(3)).await, [0xCC; 32]).0;
    let got: Arc<StdMutex<HashMap<u64, Vec<u8>>>> = Arc::new(StdMutex::new(HashMap::new()));
    let got_cb = got.clone();
    let sub = subscriber.clone();
    let subscription = tokio::spawn(async move {
        let _ = sub
            .subscribe(author_key, 0, move |i, b| {
                got_cb.lock().expect("got").insert(i, b);
            })
            .await;
    });

    // Poll until all five blocks have arrived (from the mirror), or fail at the deadline.
    let deadline = Instant::now() + T;
    loop {
        if got.lock().expect("got").len() >= 5 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "subscriber never received the feed from the mirror while the author was offline"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    subscription.abort();

    // Every block is present, in order, byte-for-byte — served by the mirror,
    // verified against the (offline) author's key.
    let blocks = got.lock().expect("got");
    for i in 0..5u64 {
        assert_eq!(
            blocks.get(&i).map(|b| b.as_slice()),
            Some(format!("msg {i}").as_bytes()),
            "block {i} tailed from the mirror must match the author's original"
        );
    }
}
