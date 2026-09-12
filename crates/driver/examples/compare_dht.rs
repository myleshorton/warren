//! Isolated loopback API benchmark matching tools/dht-compare runners.
use crypto::Keypair;
use dht_next::{Contact, Event, RoutingPolicy, Value};
use driver::next::{Node, Notice};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

async fn event(events: &mut broadcast::Receiver<Notice>, mut accepts: impl FnMut(&Event) -> bool) {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if let Notice::Dht(event) = events.recv().await.unwrap() {
                if accepts(&event) {
                    return;
                }
            }
        }
    })
    .await
    .expect("private bootstrap completed");
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    let count: usize = args.get(1).map_or(8, |v| v.parse().unwrap());
    let trials: u32 = args.get(2).map_or(12, |v| v.parse().unwrap());
    assert!([8, 9, 32, 33].contains(&count) && (1..=16).contains(&trials));
    let controlled = std::env::var_os("DHT_CONTROLLED").is_some();
    let dedicated = std::env::var_os("DHT_DEDICATED").is_some();
    let replicas: usize = std::env::var("DHT_REPLICAS").map_or(3, |v| v.parse().unwrap());
    assert!(replicas > 0 && replicas < count);
    let backend = if dedicated {
        "warren-dedicated"
    } else if controlled {
        "warren-shared"
    } else {
        "warren"
    };
    let mut threads = Vec::new();
    let mut nodes = Vec::new();
    for i in 0..count + 1 {
        let bind = async move {
            Node::bind_with_policy(
                "127.0.0.1:0".parse().unwrap(),
                Keypair::from_seed(&[i as u8 + 1; 32]),
                i < count,
                RoutingPolicy::Unrestricted,
            )
            .await
            .unwrap()
        };
        if dedicated {
            let (ready, node) = tokio::sync::oneshot::channel();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let thread = std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        ready.send(bind.await).ok().unwrap();
                        stopped.await.unwrap();
                    });
            });
            nodes.push(node.await.unwrap());
            threads.push((stop, thread));
        } else {
            nodes.push(bind.await);
        }
    }
    let contacts: Vec<_> = nodes
        .iter()
        .map(|n| Contact::new(n.id(), n.local_addr()))
        .collect();
    let mut root_events = nodes[0].subscribe();
    for peer in &contacts[1..count] {
        nodes[0].probe(*peer).await.unwrap();
        event(
            &mut root_events,
            |e| matches!(e, Event::Ready(c) if c == peer),
        )
        .await;
    }
    for node in &nodes[1..] {
        let mut events = node.subscribe();
        let query = node.bootstrap(&contacts[..1]).await.unwrap();
        event(
            &mut events,
            |e| matches!(e, Event::LookupDone { query: id, .. } if *id == query),
        )
        .await;
    }
    let writer = &nodes[count - 1];
    let reader = &nodes[count];
    println!("backend,version,nodes,trial,operation,success,elapsed_ms,replica_contacts");
    for i in 0..trials {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let mut bytes = vec![97; 256];
        bytes[..4].copy_from_slice(&i.to_be_bytes());
        let value = Value::Immutable(bytes);
        let start = Instant::now();
        let copies = if controlled {
            let mut events = writer.subscribe();
            let query = writer.lookup(value.key(), &[]).await.unwrap();
            let mut peers = Vec::new();
            event(&mut events, |e| {
                if let Event::LookupDone {
                    query: id,
                    closest,
                    timed_out,
                } = e
                {
                    if *id == query {
                        assert!(!timed_out);
                        peers = closest.iter().take(replicas).copied().collect();
                        return true;
                    }
                }
                false
            })
            .await;
            assert_eq!(peers.len(), replicas);
            let mut pending = std::collections::BTreeSet::new();
            for peer in &peers {
                pending.insert(writer.put_value(*peer, value.clone(), None).await.unwrap());
            }
            event(&mut events, |e| {
                if let Event::ValueStored {
                    request, stored, ..
                } = e
                {
                    if pending.remove(request) {
                        assert!(*stored);
                    }
                }
                pending.is_empty()
            })
            .await;
            replicas
        } else {
            writer
                .store(value.clone(), None, &[])
                .await
                .unwrap()
                .acknowledged
                .len()
        };
        println!(
            "{backend},wire-v6,{count},{i},immutable_put,{},{:.3},{copies}",
            copies > 0,
            start.elapsed().as_secs_f64() * 1000.0
        );
        if controlled {
            let mut holders = 0;
            for peer in &contacts[..count - 1] {
                let mut events = writer.subscribe();
                let request = writer.get_value(*peer, value.key()).await.unwrap();
                event(&mut events, |e| {
                    if let Event::Value {
                        request: id,
                        value: found,
                        ..
                    } = e
                    {
                        if *id == request {
                            if let Some(found) = found {
                                assert_eq!(found, &value);
                                holders += 1;
                            }
                            return true;
                        }
                    }
                    false
                })
                .await;
            }
            assert_eq!(holders, replicas, "verified replica count");
            // Verification also consumes the private-IP rate budget.
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        for operation in if controlled {
            &["immutable_get", "immutable_get_repeat"][..]
        } else {
            &["immutable_get"][..]
        } {
            let start = Instant::now();
            let fetched = reader.fetch(value.key(), &[]).await.unwrap();
            let success = fetched.value.as_ref() == Some(&value);
            println!(
                "{backend},wire-v6,{count},{i},{operation},{success},{:.3},{}",
                start.elapsed().as_secs_f64() * 1000.0,
                fetched.responses
            );
            assert!(success);
        }
    }
    for node in &nodes {
        node.shutdown().await.unwrap();
    }
    for (stop, thread) in threads {
        stop.send(()).unwrap();
        thread.join().unwrap();
    }
}
