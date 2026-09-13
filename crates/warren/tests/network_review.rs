use dht_next::{Action, Dht, Event, Time};
use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use swarm::{Contact, NodeId};
use warren::network::NextNode;

#[tokio::test]
async fn slow_pagination_keeps_initial_and_completed_page_providers() {
    let socket = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let identity = crypto::Keypair::from_seed(&[91; 32]);
    let coordinator = Contact::new(
        dht_next::node_id(identity.public()),
        socket.local_addr().unwrap(),
    );
    let topic = NodeId::from_bytes([92; 32]);
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let initial = Time::new(100_000, unix);
    let mut core = Dht::new(identity, [94; 32], true);
    let mut providers = vec![];
    // Seed real signed registrations through the core's normal cookie exchange.
    for i in 0..32u8 {
        let mut publisher = Dht::new(crypto::Keypair::from_seed(&[i; 32]), [i; 32], false);
        let address = ([127, 0, 0, 1], 4000 + u16::from(i)).into();
        let mut queue: VecDeque<_> = publisher
            .register(coordinator, topic, initial)
            .unwrap()
            .into_iter()
            .map(|a| (true, a))
            .collect();
        let mut registered = false;
        while let Some((to_coordinator, action)) = queue.pop_front() {
            match action {
                Action::Send { bytes, .. } => {
                    let replies = if to_coordinator {
                        core.receive(address, &bytes, initial)
                    } else {
                        publisher.receive(coordinator.addr, &bytes, initial)
                    };
                    queue.extend(replies.into_iter().map(|a| (!to_coordinator, a)));
                }
                Action::Event(event) if matches!(*event, Event::Registered(_)) => registered = true,
                _ => {}
            }
        }
        assert!(registered);
        providers.push(publisher.id());
    }
    providers.sort();
    let responder = tokio::spawn(async move {
        let started = Instant::now();
        let mut buffer = [0; 2048];
        let mut replies = tokio::task::JoinSet::new();
        loop {
            let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
            let time = Time::new(
                100_000 + started.elapsed().as_millis() as u64,
                unix + started.elapsed().as_secs(),
            );
            for action in core.receive(from, &buffer[..n], time) {
                if let Action::Send { to, bytes } = action {
                    let socket = socket.clone();
                    replies.spawn(async move {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        socket.send_to(&bytes, to).await.unwrap();
                    });
                }
            }
            while replies.try_join_next().is_some() {}
        }
    });
    let node = NextNode::bind_with_role(
        "127.0.0.1:0".parse().unwrap(),
        crypto::Keypair::from_seed(&[93; 32]),
        false,
    )
    .await
    .unwrap();
    node.add_contact(coordinator).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(20), node.lookup(topic))
        .await
        .unwrap();
    responder.abort();
    let found = result.expect("pagination deadline must preserve verified partial discovery");
    assert!(found.iter().any(|p| p.id == providers[0]));
    assert!(
        found.iter().any(|p| p.id == providers[2]),
        "a completed page should enrich the initial two providers"
    );
    assert!(
        found.len() < providers.len(),
        "the deadline should actually interrupt pagination"
    );
}
