//! Multi-writer causal merge, end to end over a real DHT backbone.
//!
//! The Layer-3 promise composed over the actual network: a subscriber that live-tails
//! *several* writers' feeds (Layer 2) and folds them into a [`warren::room::Room`]
//! converges to the one causally-ordered transcript every participant would compute —
//! with no shortcut, real [`driver::Node`]s on loopback.
//!
//! Two authors write a small interleaved conversation (each message carries a
//! version-vector clock of what its author had seen); a third node subscribes to both
//! feeds by key, `observe`s every delivered block into a `Room`, and its `view()`
//! settles on `a0 → b0 → a1` — a's reply-to-b after b's reply-to-a, exactly the causal
//! order, regardless of which feed's blocks happen to arrive first.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use crypto::{Keypair, PublicKey};
use driver::Node;
use swarm::Contact;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{timeout, Instant};
use transfer::Link;
use warren::record::Record;
use warren::room::Room;
use warren::session::{Keys, Session};

const LO: &str = "127.0.0.1:0";
const T: Duration = Duration::from_secs(20);

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

/// A distinct, deterministic node identity (DHT id is `hash(public key)`).
fn id(n: u8) -> Keypair {
    let mut seed = [0u8; 32];
    seed[0] = n;
    seed[1] = n.wrapping_mul(31).wrapping_add(7);
    Keypair::from_seed(&seed)
}

async fn joined(bootstrap: Contact, identity: Keypair) -> Node {
    let node = Node::bind(LO.parse().unwrap(), identity).await.unwrap();
    node.add_contact(bootstrap).await.unwrap();
    timeout(T, node.bootstrap()).await.unwrap().unwrap();
    node
}

fn make_session(node: Node, feed_seed: [u8; 32]) -> (Session, PublicKey) {
    let kp = Keypair::from_seed(&feed_seed);
    let pk = kp.public();
    let keys = Keys {
        channel_psk: b"room-psk".to_vec(),
        content_key: b"room-content-key".to_vec(),
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

/// Answer feed-by-key requests via `serve_by_key` (as Murmur's accept loop does).
fn spawn_serve_by_key(session: Session) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(ch) = session.node.next_incoming().await {
            let s = session.clone();
            let identity = session.node.identity().clone();
            tokio::spawn(async move {
                // Upgrade to an authenticated Noise session before reading the request.
                let Ok((mut link, _peer)) = transfer::NoiseLink::accept(ch, &identity).await else {
                    return;
                };
                let mut buf = [0u8; 64];
                let Ok(n) = link.recv(&mut buf).await else {
                    return;
                };
                if n >= 33 && buf[0] == warren::protocol::REQ_FEED_KEY {
                    if let Ok(pk) = <[u8; 32]>::try_from(&buf[1..33]) {
                        if let Ok(key) = crypto::PublicKey::from_bytes(&pk) {
                            s.serve_by_key(&mut link, key, &transfer::Config::default())
                                .await;
                        }
                    }
                }
            });
        }
    })
}

/// Announce a session's node id (reachability) + its own feed topic (discoverability),
/// then start serving.
async fn go_online(session: &Session) -> tokio::task::JoinHandle<()> {
    let node_id = session.node.id();
    timeout(T, session.node.announce(node_id))
        .await
        .unwrap()
        .unwrap();
    timeout(T, session.node.announce(session.own_feed_topic()))
        .await
        .unwrap()
        .unwrap();
    spawn_serve_by_key(session.clone())
}

/// Append a text message to `session`'s feed, carrying `clock` (writer→seen-len) and
/// `lamport` — as a room member would when publishing.
fn append_msg(session: &Session, clock: &[(PublicKey, u64)], lamport: u64, body: &str) {
    let rec = Record {
        author: warren::util::to_hex(&session.feed_pubkey().to_bytes()),
        content_type: "text/plain".into(),
        body: Some(body.into()),
        clock: clock
            .iter()
            .map(|(k, v)| (warren::util::to_hex(&k.to_bytes()), *v))
            .collect(),
        lamport,
        ..Default::default()
    };
    let line = serde_json::to_string(&rec).expect("encode record");
    session.log().lock().expect("log").append(line.into_bytes());
    session.appended().notify_waiters();
}

/// Subscribe `subscriber` to `feed_key`, folding every delivered block into `room`.
fn spawn_subscribe(
    subscriber: Session,
    feed_key: PublicKey,
    room: Arc<StdMutex<Room>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = subscriber
            .subscribe(feed_key, 0, move |i, bytes| {
                if let Ok(rec) = serde_json::from_slice::<Record>(&bytes) {
                    room.lock().expect("room").observe(i, rec);
                }
            })
            .await;
    })
}

#[tokio::test]
async fn a_subscriber_merges_two_writers_into_the_same_causal_order() {
    let (boot, _peers) = network(4).await;
    let bootstrap = boot.contact();

    // Two authors write an interleaved conversation. Each message's clock records what
    // its author had seen: b0 saw a0; a1 saw b0 → causal order a0 → b0 → a1.
    let (author_a, a_key) = make_session(joined(bootstrap, id(1)).await, [0xAA; 32]);
    let (author_b, b_key) = make_session(joined(bootstrap, id(2)).await, [0xBB; 32]);

    append_msg(&author_a, &[], 0, "a: hello"); // a:0
    append_msg(&author_b, &[(a_key, 1)], 1, "b: hi back"); // b:0 saw a:0
    append_msg(&author_a, &[(b_key, 1)], 2, "a: how are you"); // a:1 saw b:0

    let _serve_a = go_online(&author_a).await;
    let _serve_b = go_online(&author_b).await;

    // A subscriber tails BOTH feeds into one Room.
    let subscriber = make_session(joined(bootstrap, id(3)).await, [0xCC; 32]).0;
    let room = Arc::new(StdMutex::new(Room::new()));
    let sub_a = spawn_subscribe(subscriber.clone(), a_key, room.clone());
    let sub_b = spawn_subscribe(subscriber.clone(), b_key, room.clone());

    // Wait until all three messages have been observed.
    let deadline = Instant::now() + T;
    loop {
        if room.lock().expect("room").len() >= 3 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "subscriber did not receive both feeds' messages in time"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    sub_a.abort();
    sub_b.abort();

    // The merged view is the one causal order — a's reply follows b's, which follows
    // a's opener — no matter which feed's blocks arrived first.
    let view = room.lock().expect("room").view();
    assert!(view.pending.is_empty(), "every ancestor was present");
    let bodies: Vec<String> = view
        .ordered
        .iter()
        .map(|e| e.payload.body.clone().unwrap_or_default())
        .collect();
    assert_eq!(bodies, vec!["a: hello", "b: hi back", "a: how are you"]);
}
