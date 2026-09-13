use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;
use transfer::Link;
use warren::network::{Network, NextNode};
use warren::protocol::{REQ_BLOB, REQ_FEED, REQ_FEED_KEY};
use warren::session::{Keys, Session};

type NextSession = Session<NextNode>;

#[tokio::test]
async fn renewal_reports_missing_coordinators_without_blocking_startup() {
    let node = NextNode::bind_with_role(
        "127.0.0.1:0".parse().unwrap(),
        crypto::Keypair::from_seed(&[99; 32]),
        false,
    )
    .await
    .unwrap();
    let topic = node.id();
    let announcer = node
        .keep_announced(Duration::from_secs(30), move || vec![topic])
        .await;
    let mut status = announcer.status();
    tokio::time::timeout(Duration::from_secs(2), async {
        while status.borrow().attempted == 0 {
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(status.borrow().acknowledged, 0);
    assert!(status.borrow().last_error.is_some());
}

async fn client(seed: &NextNode, key: u8) -> NextNode {
    let node = NextNode::bind_with_role(
        "127.0.0.1:0".parse().unwrap(),
        crypto::Keypair::from_seed(&[key; 32]),
        false,
    )
    .await
    .unwrap();
    node.add_contact(seed.contact()).await.unwrap();
    node.bootstrap().await.unwrap();
    node
}

fn session(node: NextNode, feed_key: u8, directory: &std::path::Path, psk: &[u8]) -> NextSession {
    let identity = crypto::Keypair::from_seed(&[feed_key; 32]);
    let public = identity.public();
    Session::new(
        node,
        Arc::new(Mutex::new(feed::Log::new(identity))),
        Arc::new(tokio::sync::Mutex::new(blob::Store::new())),
        public,
        Keys {
            channel_psk: psk.to_vec(),
            content_key: b"content-key".to_vec(),
            channel_domain: b"test:channel".to_vec(),
            content_domain: b"test:blob".to_vec(),
            feed_domain: b"test:feed".to_vec(),
            kek_domain: b"test:kek".to_vec(),
        },
        directory.to_path_buf(),
        Arc::new(Mutex::new(vec![])),
        Arc::new(Mutex::new(HashMap::new())),
    )
}

async fn serve(session: NextSession) -> JoinHandle<()> {
    session.node.listen().await.unwrap();
    tokio::spawn(async move {
        while let Ok(incoming) = session.node.incoming().await {
            let session = session.clone();
            tokio::spawn(async move {
                let mut link = incoming.authenticate().await.unwrap();
                assert!(link.authenticated());
                let mut request = [0; 64];
                let Ok(n) = link.recv(&mut request).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let config = transfer::Config::default();
                match request[0] {
                    REQ_FEED => {
                        warren::protocol::serve_feed_tail(
                            &mut link,
                            &session.feed_pubkey(),
                            &session.log(),
                            &session.appended(),
                            &config,
                        )
                        .await;
                    }
                    REQ_FEED_KEY if n == 33 => {
                        let key = crypto::PublicKey::from_bytes(request[1..33].try_into().unwrap())
                            .unwrap();
                        session.serve_by_key(&mut link, key, &config).await;
                    }
                    REQ_BLOB => {
                        warren::protocol::serve_blob(
                            &mut link,
                            &*session.store().lock().await,
                            &config,
                        )
                        .await;
                    }
                    _ => {}
                }
            });
        }
    })
}

#[tokio::test]
async fn session_discovers_and_decrypts_a_blob_over_v6() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let seed = NextNode::bind(
            "127.0.0.1:0".parse().unwrap(),
            crypto::Keypair::from_seed(&[1; 32]),
        )
        .await
        .unwrap();
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let wrong_dir = tempfile::tempdir().unwrap();
        let author = session(client(&seed, 2).await, 22, a_dir.path(), b"secret");
        let viewer = session(client(&seed, 3).await, 23, b_dir.path(), b"secret");
        let wrong = session(client(&seed, 4).await, 24, wrong_dir.path(), b"different");
        let serving = serve(author.clone()).await;
        let payload = vec![57; 80_000];
        let record = author
            .publish("video/mp4".into(), serde_json::Map::new(), payload.clone())
            .await
            .unwrap();
        author
            .node
            .announce(author.channel_topic(warren::channel::current_epoch()))
            .await
            .unwrap();
        let discovered = viewer.discover().await;
        assert_eq!(discovered.connected, 1);
        assert_eq!(discovered.records.len(), 1);
        assert_eq!(discovered.records[0].1, author.feed_pubkey());
        assert_eq!(discovered.records[0].2, author.node.id());
        assert!(
            discovered.members.is_empty(),
            "a coordinator is not a provider socket"
        );
        assert_eq!(discovered.providers[0].id, author.node.id());
        let cache = viewer.node.bootstrap_contacts().await.unwrap();
        assert!(cache
            .iter()
            .any(|c| c.id == seed.id() && c.addr == seed.local_addr()));
        assert!(cache.iter().all(|c| c.id != author.node.id()));
        assert!(wrong.discover().await.records.is_empty());
        assert_eq!(
            viewer
                .fetch(record.blob.as_ref().unwrap(), Some(author.node.id()))
                .await
                .unwrap(),
            payload
        );
        assert!(viewer.node.inbound_datagrams() > 0);
        serving.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn v6_discovery_paginates_beyond_the_first_two_providers() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let seed = NextNode::bind(
            "127.0.0.1:0".parse().unwrap(),
            crypto::Keypair::from_seed(&[40; 32]),
        )
        .await
        .unwrap();
        let topic = swarm::NodeId::from_bytes([61; 32]);
        let mut publishers = vec![];
        for key in 41..47 {
            let node = client(&seed, key).await;
            node.announce(topic).await.unwrap();
            publishers.push(node);
        }
        let reader = client(&seed, 48).await;
        let found = reader.lookup(topic).await.unwrap();
        assert_eq!(found.len(), publishers.len());
        assert!(publishers
            .iter()
            .all(|p| found.iter().any(|m| m.id == p.id())));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn v6_mirror_serves_an_offline_authors_verified_feed() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let seed = NextNode::bind(
            "127.0.0.1:0".parse().unwrap(),
            crypto::Keypair::from_seed(&[70; 32]),
        )
        .await
        .unwrap();
        let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
        let author = session(client(&seed, 71).await, 81, dirs[0].path(), b"mirror");
        let mirror = session(client(&seed, 72).await, 82, dirs[1].path(), b"mirror");
        let viewer = session(client(&seed, 73).await, 83, dirs[2].path(), b"mirror");
        author
            .log()
            .lock()
            .unwrap()
            .append(b"verified feed".to_vec());
        let serving_author = serve(author.clone()).await;
        let serving_mirror = serve(mirror.clone()).await;
        let (replica, appended) = mirror
            .mirror_feed(author.node.id(), author.feed_pubkey())
            .await
            .unwrap();
        assert_eq!(replica.lock().unwrap().len(), 1);
        author.node.announce(author.own_feed_topic()).await.unwrap();
        let follower = {
            let mirror = mirror.clone();
            let replica = replica.clone();
            let key = author.feed_pubkey();
            tokio::spawn(async move { mirror.run_mirror(key, replica, appended).await })
        };
        author
            .publish_body(
                "text/plain".into(),
                "live update".into(),
                serde_json::Map::new(),
                std::collections::BTreeMap::new(),
                0,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while replica.lock().unwrap().len() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        follower.abort();
        serving_author.abort();
        author.node.endpoint().dht().shutdown().await.unwrap();
        let (received, key) = warren::protocol::fetch_feed(
            &viewer.node,
            mirror.node.id(),
            REQ_FEED,
            &transfer::Config::default(),
        )
        .await
        .unwrap();
        assert_eq!(key, mirror.feed_pubkey());
        assert!(received.is_empty());
        let copy = warren::protocol::fetch_replica(
            &viewer.node,
            mirror.node.id(),
            author.feed_pubkey(),
            &transfer::Config::default(),
            Arc::new(feed::MemStore::default()),
        )
        .await
        .unwrap();
        assert_eq!(copy.len(), 2);
        serving_mirror.abort();
    })
    .await
    .unwrap();
}
