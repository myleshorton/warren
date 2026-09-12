//! Sequential one-peer retrieval profile; no sockets, sleeps, loss or discovery.
use crypto::Keypair;
#[cfg(feature = "diagnostics")]
use dht_next::diagnostics;
use dht_next::{Action, Contact, Dht, Event, RoutingPolicy, Time, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Default)]
struct Traffic {
    signed: usize,
    compact: usize,
    bytes: usize,
    legs: usize,
    found: bool,
    stored: bool,
}
fn deliver(
    nodes: &mut [Dht],
    from: usize,
    actions: Vec<Action>,
    now: Time,
    value: &Value,
) -> Traffic {
    let addresses: Vec<SocketAddr> = (0..nodes.len())
        .map(|i| format!("127.0.0.1:{}", 10000 + i).parse().unwrap())
        .collect();
    let mut pending = VecDeque::from([(from, actions, 0)]);
    let mut traffic = Traffic::default();
    while let Some((from, actions, depth)) = pending.pop_front() {
        for action in actions {
            match action {
                Action::Send { to, bytes } => {
                    assert!(depth < 10, "unexpected exchange loop");
                    traffic.signed += usize::from(bytes.starts_with(b"WRD2\x06"));
                    traffic.compact += usize::from(bytes.starts_with(b"WRE3\x01"));
                    traffic.bytes += bytes.len();
                    traffic.legs = traffic.legs.max(depth + 1);
                    let to = addresses.iter().position(|addr| *addr == to).unwrap();
                    let replies = nodes[to].receive(addresses[from], &bytes, now);
                    pending.push_back((to, replies, depth + 1));
                }
                Action::Event(event) => match *event {
                    Event::ValueLookupDone { result, .. } => {
                        assert!(!result.timed_out && !result.conflicting);
                        assert_eq!(result.value.as_ref(), Some(value));
                        traffic.found = true;
                    }
                    Event::ValueStored { stored, .. } => {
                        assert!(stored);
                        traffic.stored = true;
                    }
                    _ => {}
                },
            }
        }
    }
    traffic
}
fn main() {
    let trials: usize = std::env::args().nth(1).map_or(100, |s| s.parse().unwrap());
    assert!((1..=10000).contains(&trials));
    println!("trial,phase,core_us,signed_packets,compact_packets,bytes,one_way_legs,region,calls,region_us");
    for trial in 0..trials {
        let mut nodes: Vec<_> = (1..=3)
            .map(|i| {
                Dht::with_routing_policy(
                    Keypair::from_seed(&[i; 32]),
                    [i + 10; 32],
                    i == 2,
                    RoutingPolicy::Unrestricted,
                )
            })
            .collect();
        let peer = Contact::new(nodes[1].id(), "127.0.0.1:10001".parse().unwrap());
        let now = Time::new(120000, 1700000000);
        let value = Value::Immutable(vec![97; 256]);
        let key = value.key();
        let (_, actions) = nodes[0].put_value(peer, value.clone(), None, now).unwrap();
        assert!(deliver(&mut nodes, 0, actions, now, &value).stored);
        #[cfg(feature = "diagnostics")]
        diagnostics::take();
        for phase in ["cold", "warm"] {
            let start = Instant::now();
            let (_, actions) = nodes[2].lookup_value(key, &[peer], now).unwrap();
            let traffic = deliver(&mut nodes, 2, actions, now, &value);
            let elapsed = start.elapsed().as_secs_f64() * 1e6;
            #[cfg(feature = "diagnostics")]
            let counters: Vec<_> = diagnostics::REGIONS
                .iter()
                .zip(diagnostics::take())
                .map(|(region, sample)| (format!("{region:?}"), sample.calls, sample.nanos))
                .collect();
            #[cfg(not(feature = "diagnostics"))]
            let counters = [("Uninstrumented", 0, 0)];
            assert!(traffic.found);
            assert_eq!(traffic.legs, if phase == "cold" { 4 } else { 2 });
            for (region, calls, nanos) in counters {
                println!(
                    "{trial},{phase},{elapsed:.3},{},{},{},{},{region},{},{:.3}",
                    traffic.signed,
                    traffic.compact,
                    traffic.bytes,
                    traffic.legs,
                    calls,
                    nanos as f64 / 1000.0
                );
            }
        }
    }
}
