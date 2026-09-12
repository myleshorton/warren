//! Deterministic comparison of legacy/new lookup on the same candidate set.
//! This measures one failure scenario, not general network performance.
use dht_next::Time;
fn at(seconds: u64) -> Time {
    Time::new(seconds * 1000, seconds)
}
use crypto::Keypair;
use dht_next::{node_id, Action, Contact, Dht, Event, NodeId};
use std::collections::VecDeque;
use std::net::SocketAddr;

fn main() {
    let local: SocketAddr = "192.0.2.1:4000".parse().unwrap();
    let live_addr: SocketAddr = "192.0.2.2:4000".parse().unwrap();
    let live_key = Keypair::from_seed(&[2; 32]);
    let live = Contact::new(node_id(live_key.public()), live_addr);
    let target = NodeId::from_bytes([0; 32]);
    let mut seeds = Vec::new();
    for i in 1..=20u8 {
        let mut id = [0; 32];
        id[31] = i;
        seeds.push(Contact::new(
            NodeId::from_bytes(id),
            format!("192.0.2.{}:4000", i + 100).parse().unwrap(),
        ));
    }
    seeds.push(live);

    let mut legacy = swarm::Dht::new(target);
    for seed in &seeds {
        legacy.add_contact(*seed);
    }
    legacy.find_node(target, 0);
    let mut legacy_packets = 0;
    for now in (0..=40000).step_by(500) {
        legacy.handle_timeout(now);
        while let Some(tx) = legacy.poll_transmit() {
            legacy_packets += 1;
            if tx.to == live.addr {
                let request = swarm::Packet::decode(&tx.data).unwrap();
                let response = swarm::Packet {
                    sender: live.id,
                    rid: request.rid,
                    reachable: true,
                    msg: swarm::Message::Nodes {
                        contacts: vec![],
                        peers: vec![],
                    },
                };
                legacy.handle_input(live.addr, &response.encode(), now);
            }
        }
        if let Some(swarm::Event::QueryFinished { closest, .. }) = legacy.poll_event() {
            println!(
                "legacy: found_live={} virtual_ms={now} outbound_packets={legacy_packets}",
                closest.contains(&live)
            );
            break;
        }
    }

    let mut nodes = [
        Dht::with_routing_policy(
            Keypair::from_seed(&[1; 32]),
            [31; 32],
            false,
            dht_next::RoutingPolicy::Unrestricted,
        ),
        Dht::new(live_key, [32; 32], true),
    ];
    let (_, actions) = nodes[0].lookup(target, &seeds, at(100)).unwrap();
    let mut queue: VecDeque<_> = actions.into_iter().map(|a| (0, a)).collect();
    let mut packets = 0;
    for elapsed in 0..=40 {
        for (i, node) in nodes.iter_mut().enumerate() {
            queue.extend(node.tick(at(100 + elapsed)).into_iter().map(|a| (i, a)));
        }
        while let Some((source, action)) = queue.pop_front() {
            match action {
                Action::Send { to, bytes } => {
                    packets += 1;
                    let destination = if to == local {
                        Some(0)
                    } else if to == live.addr {
                        Some(1)
                    } else {
                        None
                    };
                    if let Some(destination) = destination {
                        let from = if source == 0 { local } else { live.addr };
                        queue.extend(
                            nodes[destination]
                                .receive(from, &bytes, at(100 + elapsed))
                                .into_iter()
                                .map(|a| (destination, a)),
                        );
                    }
                }
                Action::Event(event) => {
                    if let Event::LookupDone {
                        closest, timed_out, ..
                    } = *event
                    {
                        println!("dht-next: found_live={} virtual_ms={} total_packets={packets} timed_out={timed_out}",
                        closest.contains(&live), elapsed * 1000);
                        assert!(closest.contains(&live));
                        return;
                    }
                }
            }
        }
    }
    panic!("replacement lookup did not finish");
}
