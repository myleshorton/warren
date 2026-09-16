use crypto::Keypair;
use driver::next::OverlayId;
use std::time::Duration;
use transfer::Link;
use warren::community::{Community, ConnectivityDomain};
use warren::invite::RegionalInvite;
use warren::network::{Network, NextNode};
use warren::regional::RegionalNode;

fn addr(ip: &str) -> std::net::SocketAddr {
    if ip.contains(':') {
        format!("[{ip}]:0").parse().unwrap()
    } else {
        format!("{ip}:0").parse().unwrap()
    }
}
async fn router(ip: &str, key: u8, overlay: OverlayId) -> NextNode {
    NextNode::bind_in_overlay(addr(ip), Keypair::from_seed(&[key; 32]), true, overlay)
        .await
        .unwrap()
}
async fn participant(
    key: u8,
    choice: &Community,
    domain: &ConnectivityDomain,
    local: &NextNode,
    shared: &NextNode,
    global: &NextNode,
) -> RegionalNode {
    let node = RegionalNode::bind_community(
        addr("127.0.0.1"),
        Some(addr("::1")),
        Some(addr("::1")),
        Keypair::from_seed(&[key; 32]),
        false,
        choice,
        Some(domain),
    )
    .await
    .unwrap();
    for (overlay, peer) in [
        (node.overlay(), local.contact()),
        (choice.overlay(), shared.contact()),
        (OverlayId::Global, global.contact()),
    ] {
        node.add_contact(overlay, peer).await.unwrap();
    }
    node.regional().bootstrap().await.unwrap();
    node.community_endpoint()
        .unwrap()
        .bootstrap()
        .await
        .unwrap();
    node.global().unwrap().bootstrap().await.unwrap();
    node
}

#[test]
fn persistence_is_stable_and_corruption_is_not_a_locale_reset() {
    let directory = tempfile::tempdir().unwrap();
    let fa = Community::from_locale("fa-IR").unwrap();
    let ru = Community::from_locale("ru").unwrap();
    assert_eq!(
        warren::store::load_or_select_community(directory.path(), Some(&fa), None).unwrap(),
        fa
    );
    assert_eq!(
        warren::store::load_or_select_community(directory.path(), None, None).unwrap(),
        fa
    );
    std::fs::write(directory.path().join("community.json"), b"broken").unwrap();
    assert!(warren::store::load_or_select_community(directory.path(), None, None).is_err());
    assert_eq!(
        warren::store::load_or_select_community(directory.path(), Some(&ru), None).unwrap(),
        ru
    );
}

#[test]
fn local_policy_normalizes_addresses_and_rejects_invalid_configuration() {
    let domain =
        ConnectivityDomain::new("test", &["192.0.2.0/25", "192.0.2.128/25", "2001:db8::/32"])
            .unwrap();
    for address in [
        "192.0.2.1:1",
        "192.0.2.255:1",
        "[::ffff:192.0.2.10]:1",
        "[2001:db8::1]:1",
    ] {
        assert!(domain.allows(address.parse().unwrap()));
    }
    for address in ["192.0.3.1:1", "[2001:db9::1]:1"] {
        assert!(!domain.allows(address.parse().unwrap()));
    }
    for ranges in [vec![], vec!["bad"], vec!["0.0.0.0/0"], vec!["::/0"]] {
        assert!(ConnectivityDomain::new("test", &ranges).is_err());
    }
}

#[tokio::test]
async fn language_community_keeps_domestic_discovery_when_overseas_peers_disappear() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let choice = Community::from_locale("fa-IR").unwrap();
        let domain = ConnectivityDomain::new("ir-test", &["127.0.0.1/32"]).unwrap();
        let local = router(
            "127.0.0.1",
            151,
            choice.local_overlay(domain.label()).unwrap(),
        )
        .await;
        let shared = router("::1", 152, choice.overlay()).await;
        let global = router("::1", 153, OverlayId::Global).await;
        let author = participant(154, &choice, &domain, &local, &shared, &global).await;
        let reader = participant(155, &choice, &domain, &local, &shared, &global).await;
        let topic = swarm::NodeId::from_bytes([156; 32]);
        author.listen().await.unwrap();
        let handles = author
            .keep_announced_all(Duration::from_millis(100), move || vec![topic])
            .await;
        assert_eq!(handles.len(), 3);
        for (_, handle) in &handles {
            let mut status = handle.status();
            while status.borrow().acknowledged == 0 {
                status.changed().await.unwrap();
            }
        }
        assert_eq!(
            reader
                .community_endpoint()
                .unwrap()
                .lookup(topic)
                .await
                .unwrap()[0]
                .id,
            author.id()
        );
        assert_eq!(
            reader.regional().lookup(topic).await.unwrap()[0].id,
            author.id()
        );
        let invite = RegionalInvite::create(
            &author,
            "channel".into(),
            "key".into(),
            &[],
            Duration::from_secs(600),
        )
        .await
        .unwrap();
        let invite = RegionalInvite::decode(
            "warren://",
            &invite.encode("warren://"),
            warren::util::now_secs(),
        )
        .unwrap();
        assert_eq!(invite.community_language.as_deref(), Some("fa"));
        assert_eq!(
            invite.community_bootstrap.as_ref().unwrap().overlay(),
            choice.overlay()
        );
        let mut mismatched = invite.clone();
        mismatched.community_language = Some("ru".into());
        assert!(RegionalInvite::decode(
            "warren://",
            &mismatched.encode("warren://"),
            warren::util::now_secs()
        )
        .is_none());
        let overseas = RegionalNode::bind_community(
            addr("::1"),
            None,
            None,
            Keypair::from_seed(&[158; 32]),
            false,
            &choice,
            None,
        )
        .await
        .unwrap();
        invite.join(&overseas).await.unwrap();
        assert_eq!(overseas.lookup(topic).await.unwrap()[0].id, author.id());
        overseas.shutdown().await.unwrap();
        let russian = Community::from_locale("ru").unwrap();
        assert_eq!(
            Community::select(
                None,
                Some(&invite),
                Some(&russian),
                ["en-US"],
                warren::util::now_secs()
            )
            .unwrap(),
            choice
        );
        assert_eq!(
            Community::select(
                Some(&russian),
                Some(&invite),
                None,
                ["fa"],
                warren::util::now_secs()
            )
            .unwrap(),
            russian
        );
        assert!(Community::from_invite(&invite, invite.expires).is_err());
        let snapshot = reader.bootstrap_state(reader.overlay()).await.unwrap();
        assert!(snapshot
            .contacts()
            .iter()
            .all(|peer| domain.allows(peer.addr)));

        shared.shutdown().await.unwrap();
        global.shutdown().await.unwrap();
        let newcomer = RegionalNode::bind_community(
            addr("127.0.0.1"),
            Some(addr("::1")),
            Some(addr("::1")),
            Keypair::from_seed(&[157; 32]),
            false,
            &choice,
            Some(&domain),
        )
        .await
        .unwrap();
        invite.join(&newcomer).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), newcomer.lookup(topic))
                .await
                .unwrap()
                .unwrap()[0]
                .id,
            author.id()
        );
        reader.shutdown().await.unwrap();
        let restarted = RegionalNode::bind_community(
            addr("127.0.0.1"),
            Some(addr("::1")),
            None,
            Keypair::from_seed(&[155; 32]),
            false,
            &Community::decode(&choice.encode()).unwrap(),
            Some(&domain),
        )
        .await
        .unwrap();
        restarted.restore_bootstrap(&snapshot).await.unwrap();
        assert_eq!(restarted.lookup(topic).await.unwrap()[0].id, author.id());
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
            assert_eq!(&data[..n], b"local Farsi connection");
        });
        let link = restarted.dial(author.id()).await.unwrap();
        assert!(link.authenticated());
        link.send(b"local Farsi connection").await.unwrap();
        server.await.unwrap();
        drop(handles);
        for node in [&author, &newcomer, &restarted] {
            node.shutdown().await.unwrap();
        }
        local.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn local_namespace_rejects_outside_peers_even_with_a_matching_overlay() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let choice = Community::from_locale("fa").unwrap();
        let domain = ConnectivityDomain::new("local-test", &["127.0.0.1/32"]).unwrap();
        let node = RegionalNode::bind_community(
            addr("::1"),
            Some(addr("::1")),
            None,
            Keypair::from_seed(&[160; 32]),
            true,
            &choice,
            Some(&domain),
        )
        .await
        .unwrap();
        let outsider = router("::1", 161, node.overlay()).await;
        assert!(node
            .add_contact(node.overlay(), outsider.contact())
            .await
            .is_err());
        let mut diagnostics = node
            .regional()
            .endpoint()
            .dht()
            .diagnostics()
            .subscribe()
            .unwrap();
        outsider
            .endpoint()
            .dht()
            .probe(node.regional().contact())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(node.regional().inbound_datagrams() > 0);
        let rejected = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let event = diagnostics.recv().await.unwrap();
                if event.name == "dht.packet.rejected" {
                    break event;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(rejected.error_code, "inbound_policy");
        assert!(node
            .bootstrap_state(node.overlay())
            .await
            .unwrap()
            .contacts()
            .is_empty());
        assert_eq!(outsider.endpoint().dht().routing_len().await.unwrap(), 0);
        assert!(!node
            .regional()
            .endpoint()
            .dht()
            .allows_address(outsider.local_addr()));
        node.shutdown().await.unwrap();
        outsider.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn opaque_community_invites_roundtrip_and_join_the_shared_overlay() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let shared_overlay = OverlayId::regional("opaque-community");
        let shared = router("127.0.0.1", 171, shared_overlay).await;
        let legacy = RegionalInvite {
            community_language: None,
            community_bootstrap: None,
            bootstrap: driver::next::BootstrapState::in_overlay(
                vec![shared.contact()],
                shared_overlay,
            ),
            channel_key: "channel".into(),
            content_key: "key".into(),
            expires: warren::util::now_secs() + 600,
        };
        let choice = Community::from_invite(&legacy, warren::util::now_secs()).unwrap();
        let domain = ConnectivityDomain::new("local", &["127.0.0.1/32"]).unwrap();
        let local = router(
            "127.0.0.1",
            172,
            choice.local_overlay(domain.label()).unwrap(),
        )
        .await;
        let author = RegionalNode::bind_community(
            addr("127.0.0.1"),
            Some(addr("127.0.0.1")),
            None,
            Keypair::from_seed(&[173; 32]),
            false,
            &choice,
            Some(&domain),
        )
        .await
        .unwrap();
        for peer in [&local, &shared] {
            let overlay = peer.endpoint().dht().overlay();
            author
                .restore_bootstrap(&driver::next::BootstrapState::in_overlay(
                    vec![peer.contact()],
                    overlay,
                ))
                .await
                .unwrap();
        }
        let invite = RegionalInvite::create(
            &author,
            "channel".into(),
            "key".into(),
            &[],
            Duration::from_secs(600),
        )
        .await
        .unwrap();
        assert!(invite.community_language.is_none());
        assert!(invite.community_bootstrap.is_some());
        let decoded = RegionalInvite::decode(
            "warren://",
            &invite.encode("warren://"),
            warren::util::now_secs(),
        )
        .unwrap();
        assert_eq!(
            Community::from_invite(&decoded, warren::util::now_secs()).unwrap(),
            choice
        );
        let newcomer = RegionalNode::bind_community(
            addr("127.0.0.1"),
            None,
            None,
            Keypair::from_seed(&[174; 32]),
            false,
            &choice,
            None,
        )
        .await
        .unwrap();
        decoded.join(&newcomer).await.unwrap();
        for node in [&author, &newcomer] {
            node.shutdown().await.unwrap();
        }
        local.shutdown().await.unwrap();
        shared.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn invitation_with_only_policy_rejections_fails_immediately() {
    let choice = Community::from_locale("fa").unwrap();
    let domain = ConnectivityDomain::new("local", &["127.0.0.1/32"]).unwrap();
    let node = RegionalNode::bind_community(
        addr("127.0.0.1"),
        Some(addr("127.0.0.1")),
        None,
        Keypair::from_seed(&[175; 32]),
        false,
        &choice,
        Some(&domain),
    )
    .await
    .unwrap();
    let invite = RegionalInvite {
        community_language: Some("fa".into()),
        community_bootstrap: None,
        bootstrap: driver::next::BootstrapState::in_overlay(
            vec![swarm::Contact::new(
                swarm::NodeId::from_bytes([176; 32]),
                "192.0.2.1:1234".parse().unwrap(),
            )],
            node.overlay(),
        ),
        channel_key: "channel".into(),
        content_key: "key".into(),
        expires: warren::util::now_secs() + 600,
    };
    let error = tokio::time::timeout(Duration::from_secs(1), invite.join(&node))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error
        .to_string()
        .contains("1 of 1 invite peers outside the configured domain"));
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn multiple_languages_validate_scopes_and_publish_independently() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let fa = Community::from_locale("fa").unwrap().overlay();
        let en = Community::from_locale("en").unwrap().overlay();
        let fa_router = router("127.0.0.1", 201, fa).await;
        let en_router = router("127.0.0.1", 202, en).await;
        let identity = Keypair::from_seed(&[203; 32]);
        let primary = NextNode::bind_in_overlay(addr("127.0.0.1"), identity.clone(), false, fa)
            .await
            .unwrap();
        let secondary = NextNode::bind_in_overlay(addr("127.0.0.1"), identity.clone(), false, en)
            .await
            .unwrap();
        assert!(RegionalNode::from_endpoints(primary.clone(), vec![primary.clone()]).is_err());
        assert!(RegionalNode::from_endpoints(primary.clone(), vec![en_router.clone()]).is_err());
        assert!(RegionalNode::from_endpoints(primary.clone(), vec![secondary.clone(); 5]).is_err());
        let node = RegionalNode::from_endpoints(primary, vec![secondary]).unwrap();
        node.add_contact(fa, fa_router.contact()).await.unwrap();
        node.add_contact(en, en_router.contact()).await.unwrap();
        for endpoint in node.nodes() {
            endpoint.bootstrap().await.unwrap();
        }
        let topic = swarm::NodeId::from_bytes([204; 32]);
        let handles = node
            .keep_announced_all(Duration::from_millis(100), move || vec![topic])
            .await;
        for (_, handle) in &handles {
            let mut status = handle.status();
            while status.borrow().acknowledged == 0 {
                status.changed().await.unwrap();
            }
        }
        let results = node.lookup_all_overlays(topic).await;
        assert_eq!(results.len(), 2);
        for (_, result) in results {
            assert!(result.unwrap().iter().any(|p| p.id == node.id()));
        }
        en_router.shutdown().await.unwrap();
        assert!(node
            .node(fa)
            .unwrap()
            .lookup(topic)
            .await
            .unwrap()
            .iter()
            .any(|p| p.id == node.id()));
        node.shutdown().await.unwrap();
        fa_router.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn composed_global_endpoint_is_visible_to_legacy_apis_and_invites_roundtrip() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let scope = Community::from_locale("fa").unwrap().overlay();
        let identity = Keypair::from_seed(&[210; 32]);
        let primary = NextNode::bind_in_overlay(addr("127.0.0.1"), identity.clone(), false, scope)
            .await
            .unwrap();
        let global = NextNode::bind(addr("127.0.0.1"), identity).await.unwrap();
        assert!(RegionalNode::from_endpoints(global.clone(), vec![]).is_err());
        let regional_router = router("127.0.0.1", 211, scope).await;
        let global_router = router("127.0.0.1", 212, OverlayId::Global).await;
        let node = RegionalNode::from_endpoints(primary, vec![global.clone()]).unwrap();
        assert_eq!(node.global().unwrap().local_addr(), global.local_addr());
        assert_eq!(node.nodes().count(), 2);
        node.add_contact(scope, regional_router.contact())
            .await
            .unwrap();
        node.add_contact(OverlayId::Global, global_router.contact())
            .await
            .unwrap();
        for endpoint in node.nodes() {
            endpoint.bootstrap().await.unwrap();
        }
        let topic = swarm::NodeId::from_bytes([213; 32]);
        let (local_handle, global_handle) = node
            .keep_announced(Duration::from_millis(100), move || vec![topic])
            .await;
        let global_handle = global_handle.expect("legacy global announcer");
        for handle in [&local_handle, &global_handle] {
            let mut status = handle.status();
            while status.borrow().acknowledged == 0 {
                status.changed().await.unwrap();
            }
        }
        let (local, global) = node.lookup_all(topic).await;
        assert!(local.unwrap().iter().any(|m| m.id == node.id()));
        assert!(global.unwrap().unwrap().iter().any(|m| m.id == node.id()));
        let invite = RegionalInvite::create(
            &node,
            "channel".into(),
            "content".into(),
            &[],
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert!(RegionalInvite::decode(
            "warren://",
            &invite.encode("warren://"),
            warren::util::now_secs()
        )
        .is_some());
        node.shutdown().await.unwrap();
        regional_router.shutdown().await.unwrap();
        global_router.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn composed_listener_starts_with_failed_primary_and_reports_retries() {
    let scope = Community::from_locale("fa").unwrap().overlay();
    let identity = Keypair::from_seed(&[214; 32]);
    let primary = NextNode::bind_in_overlay(addr("127.0.0.1"), identity.clone(), false, scope)
        .await
        .unwrap();
    let mut events = primary.diagnostics().subscribe().unwrap();
    primary.shutdown().await.unwrap();
    let global = NextNode::bind(addr("127.0.0.1"), identity).await.unwrap();
    let node = RegionalNode::from_endpoints(primary, vec![global]).unwrap();
    tokio::time::timeout(Duration::from_secs(1), node.listen())
        .await
        .unwrap()
        .unwrap();
    for expected in [1, 2, 4, 8] {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = events.recv().await.unwrap();
                if event.name == "network.accept.retry" {
                    assert_eq!(event.error_code, "accept_failed");
                    assert_eq!(
                        event.fields,
                        vec![("retry_count", driver::diagnostics::Value::Count(expected))]
                    );
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
    assert!(node.shutdown().await.is_err());
}

#[tokio::test]
async fn endpoint_invites_name_each_language_without_mixing_peers() {
    use warren::invite::InvitePayload;
    let en = Community::from_locale("en").unwrap();
    let fa = Community::from_locale("fa").unwrap();
    let english = router("127.0.0.1", 91, en.overlay()).await;
    let farsi = router("127.0.0.1", 91, fa.overlay()).await;
    let global = router("127.0.0.1", 91, OverlayId::Global).await;
    let node = RegionalNode::from_endpoints(english.clone(), vec![farsi.clone(), global]).unwrap();
    assert!(node
        .clone()
        .with_communities(vec![Community::from_locale("ru").unwrap()])
        .is_err());
    assert!(node
        .clone()
        .with_communities(vec![en.clone(), en.clone()])
        .is_err());
    let unnamed = node.clone();
    let node = node.with_communities(vec![en, fa]).unwrap();
    assert_eq!(
        unnamed
            .invitation_communities(&[], false)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    let empty = node.invitation_communities(&[], false).await.unwrap();
    assert_eq!(empty.len(), 2);
    assert!(empty.iter().all(|group| group.peers.is_empty()));
    let groups = node.invitation_communities(&[], true).await.unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].language, "en");
    assert_eq!(groups[0].peers[0].addr, english.contact().addr.to_string());
    assert_eq!(groups[1].language, "fa");
    assert_eq!(groups[1].peers[0].addr, farsi.contact().addr.to_string());
    let payload = InvitePayload {
        channel_key: "channel-a".into(),
        content_key: Some(String::new()),
        bootstrap: vec![],
        communities: groups.clone(),
    };
    let encoded = payload.encode("warren://").unwrap();
    let decoded = InvitePayload::decode("warren://", &encoded).unwrap();
    assert_eq!(decoded.communities, groups);
    assert_eq!(decoded.content_key(), "");
    // Another channel uses the same named discovery overlays.
    let other = InvitePayload {
        channel_key: "channel-b".into(),
        ..decoded
    };
    assert_eq!(other.communities, payload.communities);
    for include_self in [false, true] {
        let excluded = node
            .invitation_communities(&[node.id()], include_self)
            .await
            .unwrap();
        assert_eq!(excluded.len(), 2);
        assert!(excluded.iter().all(|g| g.peers.is_empty()));
    }
    node.shutdown().await.unwrap();
}
