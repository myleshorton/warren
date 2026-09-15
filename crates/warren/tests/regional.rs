use crypto::Keypair;
use driver::next::{BootstrapState, OverlayId};
use std::time::Duration;
use transfer::Link;
use warren::invite::RegionalInvite;
use warren::network::{Network, NextNode};
use warren::regional::RegionalNode;

fn address() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}
fn region() -> OverlayId {
    OverlayId::regional("ir-test")
}
async fn router(key: u8, overlay: OverlayId) -> NextNode {
    NextNode::bind_in_overlay(address(), Keypair::from_seed(&[key; 32]), true, overlay)
        .await
        .unwrap()
}
async fn client(key: u8, local: &NextNode, global: Option<&NextNode>) -> RegionalNode {
    let node = RegionalNode::bind(
        address(),
        global.map(|_| address()),
        Keypair::from_seed(&[key; 32]),
        false,
        region(),
    )
    .await
    .unwrap();
    node.add_contact(region(), local.contact()).await.unwrap();
    node.regional().bootstrap().await.unwrap();
    if let Some(global) = global {
        node.add_contact(OverlayId::Global, global.contact())
            .await
            .unwrap();
        node.global().unwrap().bootstrap().await.unwrap();
    }
    node
}

#[tokio::test]
async fn global_shutdown_allows_regional_restart_invitation_and_authenticated_transfer() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let origin = router(201, region()).await;
        let domestic = router(202, region()).await;
        domestic.add_contact(origin.contact()).await.unwrap();
        domestic.bootstrap().await.unwrap();
        let global = router(203, OverlayId::Global).await;
        let author = client(204, &domestic, Some(&global)).await;
        let reader = client(205, &domestic, Some(&global)).await;
        author.listen().await.unwrap();
        let topic = swarm::NodeId::from_bytes([210; 32]);
        let (local_renewal, global_renewal) = author
            .keep_announced(Duration::from_millis(100), move || vec![topic])
            .await;
        let mut status = global_renewal.as_ref().unwrap().status();
        while status.borrow().acknowledged == 0 {
            status.changed().await.unwrap();
        }
        assert_eq!(reader.lookup(topic).await.unwrap()[0].id, author.id());
        let cache = reader.bootstrap_state(region()).await.unwrap();
        let cache = BootstrapState::decode(&cache.encode()).unwrap();
        assert_eq!(cache.overlay(), region());
        assert!(cache.contacts().iter().all(|c| c.id != global.id()));
        let invite = RegionalInvite::create(
            &author,
            "channel".into(),
            "content".into(),
            &[origin.id()],
            Duration::from_secs(600),
        )
        .await
        .unwrap();
        assert!(invite
            .bootstrap
            .contacts()
            .iter()
            .all(|c| c.id != origin.id() && c.id != global.id()));
        let encoded = invite.encode("warren-region://");
        let invite =
            RegionalInvite::decode("warren-region://", &encoded, warren::util::now_secs()).unwrap();
        assert!(RegionalInvite::decode("warren-region://", &encoded, invite.expires).is_none());
        assert!(warren::invite::decode_invite("warren-region://", &encoded).is_none());
        assert!(RegionalInvite::create(
            &author,
            "channel".into(),
            "content".into(),
            &[origin.id(), domestic.id()],
            Duration::from_secs(600)
        )
        .await
        .is_err());

        global.shutdown().await.unwrap();
        origin.shutdown().await.unwrap();
        reader.shutdown().await.unwrap();
        let restarted = RegionalNode::bind(
            address(),
            Some(address()),
            Keypair::from_seed(&[205; 32]),
            false,
            region(),
        )
        .await
        .unwrap();
        restarted.restore_bootstrap(&cache).await.unwrap();
        let newcomer = RegionalNode::bind(
            address(),
            None,
            Keypair::from_seed(&[206; 32]),
            false,
            region(),
        )
        .await
        .unwrap();
        invite.join(&newcomer).await.unwrap();
        assert_eq!(newcomer.lookup(topic).await.unwrap()[0].id, author.id());
        let serving = author.clone();
        let server = tokio::spawn(async move {
            let link = serving
                .incoming()
                .await
                .unwrap()
                .authenticate()
                .await
                .unwrap();
            let mut data = [0; 32];
            let n = link.recv(&mut data).await.unwrap();
            assert_eq!(&data[..n], b"regional survives");
            link.send(b"verified").await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        assert_eq!(restarted.lookup(topic).await.unwrap()[0].id, author.id());
        let link = tokio::time::timeout(Duration::from_secs(10), restarted.dial(author.id()))
            .await
            .unwrap()
            .unwrap();
        assert!(link.authenticated());
        link.send(b"regional survives").await.unwrap();
        let mut data = [0; 32];
        let n = link.recv(&mut data).await.unwrap();
        assert_eq!(&data[..n], b"verified");
        server.await.unwrap();
        assert!(local_renewal.status().borrow().acknowledged > 0);
        drop((local_renewal, global_renewal));
        author.shutdown().await.unwrap();
        restarted.shutdown().await.unwrap();
        newcomer.shutdown().await.unwrap();
        domestic.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn overlay_mismatch_cannot_admit_routes_or_restore_a_cache() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let domestic = router(220, region()).await;
        let other = router(221, OverlayId::regional("other-test")).await;
        let global = router(222, OverlayId::Global).await;
        let node = client(223, &domestic, None).await;
        let state = node.bootstrap_state(region()).await.unwrap();
        assert!(global
            .endpoint()
            .dht()
            .restore_bootstrap(&state)
            .await
            .is_err());
        assert!(other
            .endpoint()
            .dht()
            .restore_bootstrap(&state)
            .await
            .is_err());
        let driver = domestic.endpoint().dht();
        driver.probe(other.contact()).await.unwrap();
        driver.probe(global.contact()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(other.inbound_datagrams() > 0);
        assert!(global.inbound_datagrams() > 0);
        assert_eq!(other.endpoint().dht().routing_len().await.unwrap(), 0);
        assert_eq!(global.endpoint().dht().routing_len().await.unwrap(), 0);
        let known = driver.bootstrap_state().await.unwrap();
        assert!(known
            .contacts()
            .iter()
            .all(|c| c.id != other.id() && c.id != global.id()));
        node.shutdown().await.unwrap();
        domestic.shutdown().await.unwrap();
        other.shutdown().await.unwrap();
        global.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn global_only_provider_is_found_when_regional_lookup_is_empty() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let domestic = router(230, region()).await;
        let global = router(231, OverlayId::Global).await;
        let author = client(232, &domestic, Some(&global)).await;
        let reader = client(233, &domestic, Some(&global)).await;
        let topic = swarm::NodeId::from_bytes([234; 32]);
        author.global().unwrap().listen().await.unwrap();
        author.global().unwrap().announce(topic).await.unwrap();
        assert!(reader.regional().lookup(topic).await.unwrap().is_empty());
        assert_eq!(reader.lookup(topic).await.unwrap()[0].id, author.id());
        let serving = author.global().unwrap().clone();
        let server = tokio::spawn(async move {
            let link = serving
                .incoming()
                .await
                .unwrap()
                .authenticate()
                .await
                .unwrap();
            let mut data = [0; 8];
            let n = link.recv(&mut data).await.unwrap();
            assert_eq!(&data[..n], b"global");
        });
        let link = reader.dial(author.id()).await.unwrap();
        link.send(b"global").await.unwrap();
        server.await.unwrap();
        let empty = swarm::NodeId::from_bytes([235; 32]);
        assert!(reader.lookup(empty).await.unwrap().is_empty());
        author.shutdown().await.unwrap();
        reader.shutdown().await.unwrap();
        domestic.shutdown().await.unwrap();
        global.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

fn session(
    node: RegionalNode,
    directory: &std::path::Path,
    seed: u8,
) -> warren::session::Session<RegionalNode> {
    use std::sync::{Arc, Mutex};
    let key = Keypair::from_seed(&[seed; 32]);
    let public = key.public();
    warren::session::Session::new(
        node,
        Arc::new(Mutex::new(feed::Log::new(key))),
        Arc::new(tokio::sync::Mutex::new(blob::Store::new())),
        public,
        warren::session::Keys {
            channel_psk: b"regional-channel".to_vec(),
            content_key: b"content".to_vec(),
            channel_domain: b"test:channel".to_vec(),
            content_domain: b"test:blob".to_vec(),
            feed_domain: b"test:feed".to_vec(),
            kek_domain: b"test:kek".to_vec(),
        },
        directory.to_path_buf(),
        Arc::new(Mutex::new(vec![])),
        Arc::new(Mutex::new(std::collections::HashMap::new())),
    )
}

#[tokio::test]
async fn session_publishes_and_decrypts_new_content_during_global_blackhole() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let domestic = router(240, region()).await;
        let global = router(241, OverlayId::Global).await;
        let author_dir = tempfile::tempdir().unwrap();
        let reader_dir = tempfile::tempdir().unwrap();
        let author = session(
            client(242, &domestic, Some(&global)).await,
            author_dir.path(),
            244,
        );
        let reader = session(
            client(243, &domestic, Some(&global)).await,
            reader_dir.path(),
            245,
        );
        author.node.listen().await.unwrap();
        global.shutdown().await.unwrap();
        let payload = vec![73; 80_000];
        let record = tokio::time::timeout(
            Duration::from_secs(5),
            author.publish(
                "application/octet-stream".into(),
                serde_json::Map::new(),
                payload.clone(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        author.node.announce(author.channel_topic(warren::channel::current_epoch())).await.unwrap();
        let serving = author.clone();
        let server = tokio::spawn(async move {
            let mut requests = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = serving.node.incoming() => {
                        let incoming = incoming.unwrap();
                        let serving = serving.clone();
                        requests.spawn(async move {
                            let mut link = incoming.authenticate().await.unwrap();
                            let mut request = [0; 64];
                            if link.recv(&mut request).await.unwrap_or(0) == 0 { return; }
                            let config = transfer::Config::default();
                            match request[0] {
                                warren::protocol::REQ_FEED => {
                                    warren::protocol::serve_feed_tail(&mut link, &serving.feed_pubkey(), &serving.log(), &serving.appended(), &config).await;
                                }
                                warren::protocol::REQ_BLOB => {
                                    warren::protocol::serve_blob(&mut link, &*serving.store().lock().await, &config).await;
                                }
                                _ => panic!("unexpected session request"),
                            }
                        });
                    }
                    result = requests.join_next(), if !requests.is_empty() => { result.unwrap().unwrap(); }
                }
            }
        });
        assert_eq!(reader.discover().await.connected, 1);
        let fetched = reader.fetch(record.blob.as_ref().unwrap(), None).await.unwrap();
        assert!(fetched == payload, "session should decrypt the verified blob using its discovered feed record");
        server.abort();
        let _ = server.await;
        author.node.shutdown().await.unwrap();
        reader.node.shutdown().await.unwrap();
        domestic.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}
