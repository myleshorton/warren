//! Exercise the replacement core over real sockets without switching the driver.
use dht_next::Time;
fn at(seconds: u64) -> Time {
    Time::new(seconds * 1000, seconds)
}
use crypto::Keypair;
use dht_next::{node_id, Action, Contact, Dht, Event};
use std::collections::VecDeque;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

#[test]
fn real_udp_automatic_publication_discovery_and_dht_signaling() {
    let sockets: Vec<_> = (0..3)
        .map(|_| {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            socket
        })
        .collect();
    let keys: Vec<_> = (1..=3).map(|n| Keypair::from_seed(&[n; 32])).collect();
    let contacts: Vec<_> = keys
        .iter()
        .zip(&sockets)
        .map(|(key, socket)| Contact::new(node_id(key.public()), socket.local_addr().unwrap()))
        .collect();
    let mut nodes: Vec<_> = keys
        .into_iter()
        .enumerate()
        .map(|(i, key)| Dht::new(key, [i as u8 + 30; 32], i == 0))
        .collect();
    let actions = nodes[1]
        .publish(contacts[1].id, &[contacts[0]], at(100))
        .unwrap();
    let mut queue: VecDeque<_> = actions.into_iter().map(|a| (1, a)).collect();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0; 1500];
    let mut signaled = false;
    while Instant::now() < deadline {
        while let Some((source, action)) = queue.pop_front() {
            match action {
                Action::Send { to, bytes } => {
                    sockets[source].send_to(&bytes, to).unwrap();
                }
                Action::Event(event) => match *event {
                    Event::Registered(_) => {
                        let (_, actions) = nodes[2]
                            .lookup(contacts[1].id, &[contacts[0]], at(100))
                            .unwrap();
                        queue.extend(actions.into_iter().map(|a| (2, a)));
                    }
                    Event::Providers { records, .. } if !signaled => {
                        let (_, actions) = nodes[2]
                            .signal(records[0].clone(), b"candidate offer".to_vec(), at(100))
                            .unwrap();
                        queue.extend(actions.into_iter().map(|a| (2, a)));
                        signaled = true;
                    }
                    Event::Incoming { signal, .. } => {
                        assert_eq!(source, 1);
                        assert_eq!(signal.payload, b"candidate offer");
                        let actions = nodes[1]
                            .answer(
                                signal.envelope.session,
                                b"candidate answer".to_vec(),
                                at(100),
                            )
                            .unwrap();
                        queue.extend(actions.into_iter().map(|a| (1, a)));
                    }
                    Event::Answered(signal) => {
                        assert_eq!(source, 2);
                        assert_eq!(signal.payload, b"candidate answer");
                        assert_eq!(node_id(signal.envelope.author), contacts[1].id);
                        assert_eq!(nodes[0].routing_len(), 0, "clients remain outside routing");
                        return;
                    }
                    _ => {}
                },
            }
        }
        for (i, socket) in sockets.iter().enumerate() {
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((size, from)) => queue.extend(
                        nodes[i]
                            .receive(from, &buf[..size], at(100))
                            .into_iter()
                            .map(|a| (i, a)),
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("UDP receive: {error}"),
                }
            }
        }
        if queue.is_empty() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    panic!("DHT-mediated UDP signaling did not complete before deadline");
}
