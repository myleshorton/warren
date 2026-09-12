use crypto::Keypair;
use dht_next::{Contact, Event, NodeId};
use driver::next::{Node, Notice};
use std::time::Duration;
use tokio::sync::broadcast;

async fn event(
    events: &mut broadcast::Receiver<Notice>,
    accepts: impl Fn(&Event) -> bool,
) -> Event {
    let mut recent = std::collections::VecDeque::new();
    let result = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            match events.recv().await.unwrap() {
                Notice::Dht(e) if accepts(&e) => return *e,
                Notice::Dht(e) => {
                    if recent.len() == 16 {
                        recent.pop_front();
                    }
                    recent.push_back(e);
                }
                other => panic!("unexpected driver notice: {other:?}"),
            }
        }
    })
    .await;
    result.unwrap_or_else(|_| panic!("DHT event before deadline; unmatched events: {recent:#?}"))
}
async fn bind(host: &str, key: u8, server: bool) -> Node {
    Node::bind(
        format!("{host}:0").parse().unwrap(),
        Keypair::from_seed(&[key; 32]),
        server,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn replacement_driver_publishes_pages_discovers_and_fails_over_signaling() {
    signaling_scenario().await;
}

#[tokio::test]
#[ignore = "100 real-UDP publication/discovery/failover trials"]
async fn signaling_soak() {
    for trial in 1..=100 {
        eprintln!("signaling trial {trial}/100");
        signaling_scenario().await;
    }
}

async fn signaling_scenario() {
    let first = bind("127.0.0.1", 1, true).await;
    let second = bind("[::1]", 2, true).await;
    let provider = bind("[::]", 3, false).await;
    let caller = bind("[::]", 4, false).await;
    let seeds = [
        Contact::new(first.id(), first.local_addr()),
        Contact::new(second.id(), second.local_addr()),
    ];
    let mut provider_events = provider.subscribe();
    let mut caller_events = caller.subscribe();
    let topic = NodeId::from_bytes([99; 32]);
    provider.publish(topic, &seeds).await.unwrap();
    for _ in 0..2 {
        event(
            &mut provider_events,
            |e| matches!(e, Event::Registered(r) if r.topic == topic),
        )
        .await;
    }
    let query = caller.lookup(topic, &seeds).await.unwrap();
    let mut records = Vec::new();
    loop {
        let e = event(&mut caller_events, |e| matches!(e, Event::Providers { query: id, .. } | Event::LookupDone { query: id, .. } if *id == query)).await;
        match e {
            Event::Providers { records: found, .. } => records.extend(found),
            Event::LookupDone {
                timed_out: false, ..
            } => break,
            _ => panic!("lookup timed out"),
        }
    }
    assert_eq!(records.len(), 2);
    let request = caller.providers_page(seeds[0], topic, None).await.unwrap();
    let page = event(
        &mut caller_events,
        |e| matches!(e, Event::ProviderPage { request: id, .. } if *id == request),
    )
    .await;
    assert!(matches!(page, Event::ProviderPage { records, next: None, .. } if records.len() == 1));
    records.sort_by_key(|r| r.coordinator.id != first.id());
    first.shutdown().await.unwrap();
    let session = caller
        .signal_via(&records, b"candidate offer".to_vec())
        .await
        .unwrap();
    let incoming = event(
        &mut provider_events,
        |e| matches!(e, Event::Incoming { signal, .. } if signal.envelope.session == session),
    )
    .await;
    assert!(
        matches!(incoming, Event::Incoming { signal, .. } if signal.payload == b"candidate offer")
    );
    provider
        .answer(session, b"candidate answer".to_vec())
        .await
        .unwrap();
    let answer = event(
        &mut caller_events,
        |e| matches!(e, Event::Answered(signal) if signal.envelope.session == session),
    )
    .await;
    assert!(matches!(answer, Event::Answered(signal) if signal.payload == b"candidate answer"));
    assert!(provider.unpublish(topic).await.unwrap());
    for node in [&second, &provider, &caller] {
        node.shutdown().await.unwrap();
    }
    assert_eq!(caller.routing_len().await, Err(driver::next::Error::Closed));
    let socket = tokio::net::UdpSocket::bind(caller.local_addr())
        .await
        .unwrap();
    assert_eq!(socket.local_addr().unwrap(), caller.local_addr());
}

#[tokio::test]
async fn driver_rejects_oversized_commands_and_bounds_slow_subscribers() {
    let server = bind("127.0.0.1", 5, true).await;
    let caller = bind("127.0.0.1", 6, false).await;
    let mut events = caller.subscribe();
    assert_eq!(
        caller.answer([0; 32], vec![0; 257]).await,
        Err(driver::next::Error::Core(dht_next::Error::Invalid))
    );
    // Empty lookups complete locally, allowing channel overflow without network load.
    for n in 0..300u16 {
        let mut topic = [0; 32];
        topic[..2].copy_from_slice(&n.to_le_bytes());
        caller.lookup(NodeId::from_bytes(topic), &[]).await.unwrap();
    }
    // Barrier: all previous command actions have been delivered before this read.
    caller.routing_len().await.unwrap();
    assert!(matches!(
        events.recv().await,
        Err(broadcast::error::RecvError::Lagged(_))
    ));
    caller.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn replacement_driver_stores_immutable_and_cas_mutable_values() {
    let server = bind("127.0.0.1", 7, true).await;
    let writer = bind("127.0.0.1", 8, false).await;
    let coordinator = Contact::new(server.id(), server.local_addr());
    let mut events = writer.subscribe();
    let value = dht_next::Value::Immutable(b"content addressed".to_vec());
    let request = writer
        .put_value(coordinator, value.clone(), None)
        .await
        .unwrap();
    event(
        &mut events,
        |e| matches!(e, Event::ValueStored { request: id, stored: true, .. } if *id == request),
    )
    .await;
    let request = writer.get_value(coordinator, value.key()).await.unwrap();
    event(&mut events, |e| matches!(e, Event::Value { request: id, value: Some(got), .. } if *id == request && got == &value)).await;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let signed = |seq, bytes: &[u8]| {
        dht_next::Value::from(
            dht_next::MutableValue::sign(
                &Keypair::from_seed(&[9; 32]),
                vec![],
                seq,
                bytes.to_vec(),
                expires,
            )
            .unwrap(),
        )
    };
    let one = signed(1, b"one");
    let request = writer
        .put_value(coordinator, one.clone(), None)
        .await
        .unwrap();
    event(
        &mut events,
        |e| matches!(e, Event::ValueStored { request: id, stored: true, .. } if *id == request),
    )
    .await;
    let two = signed(2, b"two");
    let request = writer
        .put_value(coordinator, two.clone(), Some(0))
        .await
        .unwrap();
    event(
        &mut events,
        |e| matches!(e, Event::ValueStored { request: id, stored: false, .. } if *id == request),
    )
    .await;
    let request = writer
        .put_value(coordinator, two.clone(), Some(1))
        .await
        .unwrap();
    event(
        &mut events,
        |e| matches!(e, Event::ValueStored { request: id, stored: true, .. } if *id == request),
    )
    .await;
    let request = writer.get_value(coordinator, one.key()).await.unwrap();
    event(&mut events, |e| matches!(e, Event::Value { request: id, value: Some(got), .. } if *id == request && got == &two)).await;
    assert_eq!(
        server.routing_len().await.unwrap(),
        0,
        "successful client writes must not grant routing eligibility"
    );
    writer.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn replica_api_reports_partial_cas_and_conflicting_signed_values() {
    let mut nodes = Vec::new();
    for n in 10..14 {
        nodes.push(
            Node::bind_with_policy(
                "127.0.0.1:0".parse().unwrap(),
                Keypair::from_seed(&[n; 32]),
                n < 13,
                dht_next::RoutingPolicy::Unrestricted,
            )
            .await
            .unwrap(),
        );
    }
    let seeds: Vec<_> = nodes[..3]
        .iter()
        .map(|n| Contact::new(n.id(), n.local_addr()))
        .collect();
    let client = &nodes[3];
    let immutable = dht_next::Value::Immutable(b"replicated".to_vec());
    let stored = client.store(immutable.clone(), None, &seeds).await.unwrap();
    assert_eq!(stored.acknowledged.len(), 3);
    let fetched = client.fetch(immutable.key(), &seeds).await.unwrap();
    assert_eq!(fetched.responses, 1);
    assert!(!fetched.timed_out);
    assert_eq!(fetched.attempted, 3);
    assert_eq!(fetched.value, Some(immutable));
    let absent = client
        .fetch(NodeId::from_bytes([33; 32]), &seeds)
        .await
        .unwrap();
    assert_eq!(absent.responses, 3);
    assert_eq!(absent.value, None);
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let signed = |seq, bytes: &[u8]| {
        dht_next::Value::from(
            dht_next::MutableValue::sign(
                &Keypair::from_seed(&[42; 32]),
                vec![],
                seq,
                bytes.to_vec(),
                expires,
            )
            .unwrap(),
        )
    };
    let one = signed(1, b"one");
    assert_eq!(
        client
            .store(one.clone(), None, &seeds)
            .await
            .unwrap()
            .acknowledged
            .len(),
        3
    );
    let two = signed(2, b"two");
    let mut events = client.subscribe();
    let request = client
        .put_value(seeds[0], two.clone(), Some(1))
        .await
        .unwrap();
    event(
        &mut events,
        |e| matches!(e, Event::ValueStored { request: id, stored: true, .. } if *id == request),
    )
    .await;
    assert_eq!(
        client.fetch(one.key(), &seeds).await.unwrap().value,
        Some(two)
    );
    let request = client
        .put_value(seeds[1], signed(2, b"fork"), Some(1))
        .await
        .unwrap();
    event(
        &mut events,
        |e| matches!(e, Event::ValueStored { request: id, stored: true, .. } if *id == request),
    )
    .await;
    assert!(matches!(
        client.fetch(one.key(), &seeds).await,
        Err(driver::next::Error::ConflictingValues)
    ));
    let partial = client
        .store(signed(3, b"three"), Some(1), &seeds)
        .await
        .unwrap();
    assert_eq!(partial.acknowledged.len(), 1);
    assert_eq!(partial.rejected.len(), 2);
    assert!(partial.timed_out.is_empty());
    for node in &nodes {
        node.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn restart_bootstrap_revalidates_persisted_contacts() {
    let router = bind("127.0.0.1", 140, true).await;
    let first = bind("127.0.0.1", 141, false).await;
    let mut events = first.subscribe();
    let query = first
        .bootstrap(&[Contact::new(router.id(), router.local_addr())])
        .await
        .unwrap();
    event(
        &mut events,
        |e| matches!(e, Event::LookupDone { query: q, .. } if *q == query),
    )
    .await;
    let encoded = first.bootstrap_state().await.unwrap().encode();
    let state = driver::next::BootstrapState::decode(&encoded).unwrap();
    assert_eq!(state.contacts().len(), 1);
    first.shutdown().await.unwrap();
    let restarted = bind("127.0.0.1", 141, false).await;
    assert_eq!(restarted.routing_len().await.unwrap(), 0);
    let mut events = restarted.subscribe();
    let query = restarted.restore_bootstrap(&state).await.unwrap();
    event(
        &mut events,
        |e| matches!(e, Event::LookupDone { query: q, timed_out: false, .. } if *q == query),
    )
    .await;
    assert_eq!(restarted.routing_len().await.unwrap(), 1);
    restarted.shutdown().await.unwrap();
    router.shutdown().await.unwrap();
}
