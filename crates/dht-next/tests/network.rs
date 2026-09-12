use dht_next::Time;
fn at(seconds: u64) -> Time {
    Time::new(seconds * 1000, seconds)
}
use crypto::Keypair;
use dht_next::{node_id, Action, Contact, Dht, Error, Event, NodeId, Record, MAX_PENDING};
use std::collections::VecDeque;
use std::net::SocketAddr;

fn address(n: u8) -> SocketAddr {
    format!("192.0.{n}.1:4000").parse().unwrap()
}
fn identity(n: u8) -> Keypair {
    Keypair::from_seed(&[n; 32])
}
fn contact(n: u8) -> Contact {
    Contact::new(node_id(identity(n).public()), address(n))
}

struct Network {
    nodes: Vec<(SocketAddr, Dht)>,
    events: Vec<(usize, Event)>,
    packets: Vec<(SocketAddr, SocketAddr)>,
    now: u64,
}
impl Network {
    fn new(roles: &[bool]) -> Self {
        Self {
            nodes: roles
                .iter()
                .enumerate()
                .map(|(i, server)| {
                    let n = i as u8 + 1;
                    (address(n), Dht::new(identity(n), [n + 32; 32], *server))
                })
                .collect(),
            events: Vec::new(),
            packets: Vec::new(),
            now: 100,
        }
    }
    fn pump(&mut self, source: usize, actions: Vec<Action>) {
        self.pump_with(source, actions, |_, _, _| false);
    }
    fn pump_with(
        &mut self,
        source: usize,
        actions: Vec<Action>,
        mut drop: impl FnMut(SocketAddr, SocketAddr, &[u8]) -> bool,
    ) {
        let mut queue: VecDeque<_> = actions.into_iter().map(|a| (source, a)).collect();
        let mut steps = 0;
        while let Some((source, action)) = queue.pop_front() {
            steps += 1;
            assert!(steps < 10000, "protocol loop");
            match action {
                Action::Event(event) => self.events.push((source, *event)),
                Action::Send { to, bytes } => {
                    assert!(bytes.len() <= dht_next::protocol::MAX_PACKET);
                    let from = self.nodes[source].0;
                    self.packets.push((from, to));
                    if drop(from, to, &bytes) {
                        continue;
                    }
                    if let Some(dest) = self.nodes.iter().position(|(addr, _)| *addr == to) {
                        let actions = self.nodes[dest].1.receive(from, &bytes, at(self.now));
                        queue.extend(actions.into_iter().map(|a| (dest, a)));
                    }
                }
            }
        }
    }
    fn tick(&mut self) {
        self.now += 1;
        for i in 0..self.nodes.len() {
            let actions = self.nodes[i].1.tick(at(self.now));
            self.pump(i, actions);
        }
    }
    fn register(&mut self, provider: usize, coordinator: usize, topic: NodeId) -> Record {
        let actions = self.nodes[provider]
            .1
            .register(contact(coordinator as u8 + 1), topic, at(self.now))
            .unwrap();
        self.pump(provider, actions);
        self.events
            .iter()
            .rev()
            .find_map(|(i, e)| match e {
                Event::Registered(r) if *i == provider => Some(r.clone()),
                _ => None,
            })
            .unwrap()
    }
}

#[test]
fn decentralized_discovery_and_signaling_between_nonrouting_clients() {
    let mut n = Network::new(&[true, true, false, false]);
    let topic = contact(3).id;
    let first = n.register(2, 0, topic);
    let second = n.register(2, 1, topic);
    assert_eq!(
        n.nodes[0].1.routing_len(),
        0,
        "registered clients must not become routers"
    );
    let actions = n.nodes[0].1.probe(contact(2), at(n.now)).unwrap();
    n.pump(0, actions);
    let (query, actions) = n.nodes[3]
        .1
        .lookup(topic, &[contact(1)], at(n.now))
        .unwrap();
    n.pump(3, actions);
    let records: Vec<_> = n
        .events
        .iter()
        .filter_map(|(i, e)| match e {
            Event::Providers { query: q, records } if *i == 3 && *q == query => {
                Some(records.clone())
            }
            _ => None,
        })
        .flatten()
        .collect();
    assert!(
        records.contains(&first) && records.contains(&second),
        "lookup walks the DHT to both coordinators"
    );
    for record in records {
        let before = n.packets.len();
        let (session, actions) = n.nodes[3]
            .1
            .signal(record.clone(), b"offer candidates".to_vec(), at(n.now))
            .unwrap();
        n.pump(3, actions);
        assert!(n
            .events
            .iter()
            .any(|(i, e)| matches!(e, Event::Incoming { signal, .. }
            if *i == 2 && signal.envelope.session == session && signal.payload == b"offer candidates")));
        let actions = n.nodes[2]
            .1
            .answer(session, b"answer candidates".to_vec(), at(n.now))
            .unwrap();
        n.pump(2, actions);
        assert!(n
            .events
            .iter()
            .any(|(i, e)| matches!(e, Event::Answered(signal)
            if *i == 3 && signal.envelope.session == session && signal.payload == b"answer candidates")));
        for (from, to) in &n.packets[before..] {
            assert!(
                *from == record.coordinator.addr || *to == record.coordinator.addr,
                "all signaling traverses the selected DHT coordinator"
            );
        }
        assert_eq!(
            n.nodes[2].1.answer(session, vec![], at(n.now)),
            Err(Error::UnknownSession)
        );
    }
}

#[test]
fn bootstrap_requires_a_completed_challenge_exchange() {
    let mut n = Network::new(&[true, true]);
    let actions = n.nodes[0].1.probe(contact(2), at(n.now)).unwrap();
    let Action::Send { bytes, .. } = &actions[0] else {
        panic!()
    };
    let response = n.nodes[1].1.receive(address(1), bytes, at(n.now));
    assert_eq!(n.nodes[1].1.routing_len(), 0);
    assert_eq!(n.nodes[0].1.routing_len(), 0);
    let Action::Send {
        bytes: challenge, ..
    } = &response[0]
    else {
        panic!()
    };
    assert!(
        challenge.len() <= bytes.len(),
        "no unvalidated amplification"
    );
    n.pump(1, response);
    assert_eq!(n.nodes[0].1.routing_len(), 1);
    assert_eq!(n.nodes[1].1.routing_len(), 1);
}

#[test]
fn failed_nearest_twenty_do_not_hide_a_farther_live_peer() {
    let mut n = Network::new(&[false, true]);
    let target = NodeId::from_bytes([0; 32]);
    let mut seeds = Vec::new();
    for i in 1..=20u8 {
        let mut id = [0; 32];
        id[31] = i;
        seeds.push(Contact::new(NodeId::from_bytes(id), address(i + 100)));
    }
    seeds.push(contact(2));
    let (query, actions) = n.nodes[0].1.lookup(target, &seeds, at(n.now)).unwrap();
    n.pump(0, actions);
    for _ in 0..35 {
        n.tick();
    }
    assert!(n.events.iter().any(
        |(i, e)| matches!(e, Event::LookupDone { query: q, closest, timed_out: false }
        if *i == 0 && *q == query && closest.contains(&contact(2)))
    ));
}

#[test]
fn lost_registration_ack_recovers_without_duplicate_effects() {
    let mut n = Network::new(&[true, false]);
    let actions = n.nodes[1]
        .1
        .register(contact(1), contact(2).id, at(n.now))
        .unwrap();
    let mut responses = 0;
    n.pump_with(1, actions, |from, _, _| {
        if from == address(1) {
            responses += 1;
            responses == 2
        } else {
            false
        }
    });
    assert_eq!(n.nodes[0].1.registration_len(), 1);
    assert!(!n
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::Registered(_))));
    n.tick();
    assert_eq!(n.nodes[0].1.registration_len(), 1);
    assert_eq!(
        n.events
            .iter()
            .filter(|(_, e)| matches!(e, Event::Registered(_)))
            .count(),
        1
    );
}

#[test]
fn dead_coordinator_does_not_prevent_using_an_independent_registration() {
    let mut n = Network::new(&[true, true, false, false]);
    let first = n.register(2, 0, contact(3).id);
    let second = n.register(2, 1, contact(3).id);
    let (failed, _dropped) = n.nodes[3].1.signal(first, vec![], at(n.now)).unwrap();
    let (_, actions) = n.nodes[3].1.signal(second, vec![], at(n.now)).unwrap();
    n.pump(3, actions);
    let session = n
        .events
        .iter()
        .find_map(|(i, e)| match e {
            Event::Incoming { signal, .. } if *i == 2 => Some(signal.envelope.session),
            _ => None,
        })
        .unwrap();
    let actions = n.nodes[2].1.answer(session, vec![], at(n.now)).unwrap();
    n.pump(2, actions);
    assert!(n
        .events
        .iter()
        .any(|(i, e)| matches!(e, Event::Answered(s) if *i == 3 && s.envelope.session != failed)));
}

#[test]
fn leases_expire_and_pending_work_is_bounded() {
    let mut n = Network::new(&[true, false]);
    let record = n.register(1, 0, contact(2).id);
    n.now = record.expires;
    n.nodes[0].1.tick(at(n.now));
    assert_eq!(n.nodes[0].1.registration_len(), 0);
    assert_eq!(
        n.nodes[1].1.signal(record, vec![], at(n.now)),
        Err(Error::Invalid)
    );
    for _ in 0..MAX_PENDING {
        n.nodes[0].1.probe(contact(2), at(n.now)).unwrap();
    }
    assert_eq!(
        n.nodes[0].1.probe(contact(2), at(n.now)),
        Err(Error::Capacity)
    );
    assert_eq!(n.nodes[0].1.pending_len(), MAX_PENDING);
    n.nodes[0].1.tick(at(n.now + 9));
    assert_eq!(n.nodes[0].1.pending_len(), 0);
}

#[test]
fn renewing_registration_preserves_a_callers_still_valid_record() {
    let mut n = Network::new(&[true, false, false]);
    let old = n.register(1, 0, contact(2).id);
    n.now += 10;
    let newer = n.register(1, 0, contact(2).id);
    assert!(newer.expires > old.expires);
    let (session, actions) = n.nodes[2].1.signal(old, vec![], at(n.now)).unwrap();
    n.pump(2, actions);
    assert!(n
        .events
        .iter()
        .any(|(i, e)| matches!(e, Event::Incoming { signal, .. }
        if *i == 1 && signal.envelope.session == session)));
}

#[test]
fn automatic_failover_uses_a_live_coordinator_and_ignores_a_delayed_path() {
    let mut n = Network::new(&[true, true, false, false]);
    let records = [
        n.register(2, 0, contact(3).id),
        n.register(2, 1, contact(3).id),
    ];
    let (session, delayed) = n.nodes[3]
        .1
        .signal_via(&records, b"offer".to_vec(), at(n.now))
        .unwrap();
    n.now += 2;
    let actions = n.nodes[3].1.tick(at(n.now));
    n.pump_with(3, actions, |from, to, _| {
        from == address(1) || to == address(1)
    });
    assert_eq!(
        n.events
            .iter()
            .filter(|(i, e)| *i == 2 && matches!(e, Event::Incoming { .. }))
            .count(),
        1
    );
    let actions = n.nodes[2]
        .1
        .answer(session, b"answer".to_vec(), at(n.now))
        .unwrap();
    n.pump(2, actions);
    assert_eq!(n.nodes[3].1.pending_len(), 0);
    n.pump(3, delayed);
    assert_eq!(
        n.events
            .iter()
            .filter(|(i, e)| *i == 2 && matches!(e, Event::Incoming { .. }))
            .count(),
        1
    );
    assert_eq!(
        n.events
            .iter()
            .filter(|(i, e)| *i == 3
                && matches!(e, Event::Answered(s)
        if s.envelope.session == session && s.payload == b"answer"))
            .count(),
        1
    );
}

#[test]
fn failed_answer_path_recovers_without_a_second_application_answer() {
    let mut n = Network::new(&[true, true, false, false]);
    let records = [
        n.register(2, 0, contact(3).id),
        n.register(2, 1, contact(3).id),
    ];
    let actions = n.nodes[3].1.probe(contact(1), at(n.now)).unwrap();
    n.pump(3, actions);
    let (session, actions) = n.nodes[3]
        .1
        .signal_via(&records, b"offer".to_vec(), at(n.now))
        .unwrap();
    n.pump_with(3, actions, |from, to, _| {
        from == address(1) && to == address(4)
    });
    let actions = n.nodes[2]
        .1
        .answer(session, b"answer".to_vec(), at(n.now))
        .unwrap();
    n.pump_with(2, actions, |from, to, _| {
        from == address(1) && to == address(4)
    });
    assert!(!n
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::Answered(_))));
    n.now += 2;
    let actions = n.nodes[3].1.tick(at(n.now));
    n.pump_with(3, actions, |from, to, _| {
        from == address(1) && to == address(4)
    });
    assert_eq!(
        n.events
            .iter()
            .filter(|(i, e)| *i == 2 && matches!(e, Event::Incoming { .. }))
            .count(),
        1
    );
    assert_eq!(
        n.events
            .iter()
            .filter(|(i, e)| *i == 3
                && matches!(e, Event::Answered(s)
        if s.envelope.session == session && s.payload == b"answer"))
            .count(),
        1
    );
}

#[test]
fn two_delivered_paths_share_one_offer_and_one_completion() {
    let mut n = Network::new(&[true, true, false, false]);
    let records = [
        n.register(2, 0, contact(3).id),
        n.register(2, 1, contact(3).id),
    ];
    let (session, actions) = n.nodes[3]
        .1
        .signal_via(&records, vec![], at(n.now))
        .unwrap();
    n.pump(3, actions);
    n.now += 2;
    let actions = n.nodes[3].1.tick(at(n.now));
    n.pump(3, actions);
    assert_eq!(
        n.events
            .iter()
            .filter(|(i, e)| *i == 2 && matches!(e, Event::Incoming { .. }))
            .count(),
        1
    );
    let actions = n.nodes[2].1.answer(session, vec![], at(n.now)).unwrap();
    n.pump(2, actions);
    assert_eq!(
        n.events
            .iter()
            .filter(|(i, e)| *i == 3 && matches!(e, Event::Answered(_)))
            .count(),
        1
    );
    assert_eq!(n.nodes[3].1.pending_len(), 0);
}

#[test]
fn managed_registration_renews_across_multiple_lease_periods_and_stops_cleanly() {
    let mut n = Network::new(&[true, false, false]);
    let topic = contact(2).id;
    let actions = n.nodes[1]
        .1
        .maintain_registration(contact(1), topic, at(n.now))
        .unwrap();
    n.pump(1, actions);
    let first = n
        .events
        .iter()
        .find_map(|(_, e)| match e {
            Event::Registered(r) => Some(r.clone()),
            _ => None,
        })
        .unwrap();
    let deadline = n.nodes[1].1.poll_timeout().unwrap();
    assert!((295_000..=310_000).contains(&deadline));
    assert!(n.nodes[1]
        .1
        .maintain_registration(contact(1), topic, at(n.now))
        .unwrap()
        .is_empty());
    assert_eq!(n.nodes[1].1.poll_timeout(), Some(deadline));
    for _ in 0..3 {
        n.now = n.nodes[1].1.poll_timeout().unwrap().div_ceil(1000);
        let actions = n.nodes[1].1.tick(at(n.now));
        n.pump(1, actions);
        assert_eq!(n.nodes[0].1.registration_len(), 1);
        assert!(n.nodes[1].1.poll_timeout().unwrap() > n.now * 1000);
    }
    let records: Vec<_> = n
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Registered(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(records.len(), 4);
    assert!(records.windows(2).all(|r| r[1].expires > r[0].expires));
    assert!(n.now > first.expires);
    let latest = (*records.last().unwrap()).clone();
    let last_expiry = latest.expires;
    let (session, actions) = n.nodes[2]
        .1
        .signal(latest, b"still reachable".to_vec(), at(n.now))
        .unwrap();
    n.pump(2, actions);
    let actions = n.nodes[1]
        .1
        .answer(session, b"renewed path".to_vec(), at(n.now))
        .unwrap();
    n.pump(1, actions);
    assert!(n.events.iter().any(|(i, e)| *i == 2
        && matches!(e, Event::Answered(s)
        if s.envelope.session == session && s.payload == b"renewed path")));
    assert!(n.nodes[1].1.stop_renewing(topic, contact(1).id));
    let key_retirement = n.nodes[1].1.poll_timeout().unwrap();
    assert!(key_retirement > n.now * 1000 && key_retirement <= last_expiry * 1000);
    n.now = last_expiry;
    let out = n.nodes[0].1.tick(at(n.now));
    n.pump(0, out);
    assert_eq!(n.nodes[0].1.registration_len(), 0);
    assert!(n.nodes[1].1.tick(at(n.now)).is_empty());
    assert_eq!(n.nodes[1].1.poll_timeout(), None);
}

#[test]
fn one_failed_managed_coordinator_does_not_block_the_other() {
    let mut n = Network::new(&[true, true, false]);
    let topic = contact(3).id;
    for coordinator in [0, 1] {
        let actions = n.nodes[2]
            .1
            .maintain_registration(contact(coordinator + 1), topic, at(n.now))
            .unwrap();
        n.pump(2, actions);
    }
    for second in 101..=550 {
        n.now = second;
        let actions = n.nodes[2].1.tick(at(n.now));
        n.pump_with(2, actions, |from, to, _| {
            from == address(1) || to == address(1)
        });
    }
    let renewals: Vec<_> = n
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Registered(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(
        renewals
            .iter()
            .filter(|r| r.coordinator == contact(1))
            .count(),
        1
    );
    assert!(
        renewals
            .iter()
            .filter(|r| r.coordinator == contact(2))
            .count()
            >= 3
    );
    assert!(renewals.last().unwrap().expires > n.now);
    assert!(n.nodes[2].1.pending_len() <= 2);
    // The failed path remains managed and recovers when its endpoint returns.
    for second in 551..=600 {
        n.now = second;
        let actions = n.nodes[2].1.tick(at(n.now));
        n.pump(2, actions);
    }
    assert!(n.events.iter().any(
        |(_, e)| matches!(e,Event::Registered(r) if r.coordinator==contact(1)&&r.expires>600)
    ));
}

#[test]
fn publication_retries_a_partial_bootstrap_before_normal_refresh() {
    let mut n = Network::new(&[true, true, false]);
    let topic = contact(3).id;
    let actions = n.nodes[2]
        .1
        .publish(topic, &[contact(1), contact(2)], at(n.now))
        .unwrap();
    n.pump_with(2, actions, |from, to, _| {
        from == address(2) || to == address(2)
    });
    for _ in 0..4 {
        n.now += 1;
        for index in 0..n.nodes.len() {
            let actions = n.nodes[index].1.tick(at(n.now));
            n.pump_with(index, actions, |from, to, _| {
                from == address(2) || to == address(2)
            });
        }
    }
    let registrations = |n: &Network| {
        n.events
            .iter()
            .filter(|(source, event)| *source == 2 && matches!(event, Event::Registered(_)))
            .count()
    };
    assert_eq!(registrations(&n), 1);
    for _ in 0..6 {
        n.tick();
    }
    assert_eq!(registrations(&n), 2);
}

#[test]
fn publishing_discovers_coordinators_and_enables_encrypted_signaling() {
    let mut n = Network::new(&[true, true, true, true, false, false]);
    // The provider knows one bootstrap server; referrals reveal the others.
    for server in 1..4 {
        let actions = n.nodes[0].1.probe(contact(server + 1), at(n.now)).unwrap();
        n.pump(0, actions);
    }
    let topic = contact(5).id;
    let actions = n.nodes[4]
        .1
        .publish(topic, &[contact(1)], at(n.now))
        .unwrap();
    n.pump(4, actions);
    let records: Vec<_> = n
        .events
        .iter()
        .filter_map(|(i, e)| match e {
            Event::Registered(r) if *i == 4 => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(records.len(), 3);
    assert!(!n
        .events
        .iter()
        .any(|(i, e)| *i == 4 && matches!(e, Event::LookupDone { .. } | Event::Providers { .. })));
    let before = n.packets.len();
    let actions = n.nodes[4]
        .1
        .publish(topic, &[contact(1)], at(n.now))
        .unwrap();
    n.pump(4, actions);
    assert_eq!(n.packets.len(), before);
    // The caller discovers the registration using the public lookup API.
    let (_, actions) = n.nodes[5]
        .1
        .lookup(topic, &[contact(1)], at(n.now))
        .unwrap();
    n.pump(5, actions);
    let discovered: Vec<_> = n
        .events
        .iter()
        .filter_map(|(i, e)| match e {
            Event::Providers { records, .. } if *i == 5 => Some(records.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(!discovered.is_empty());
    let (session, actions) = n.nodes[5]
        .1
        .signal_via(&discovered, b"discovered offer".to_vec(), at(n.now))
        .unwrap();
    n.pump(5, actions);
    let actions = n.nodes[4]
        .1
        .answer(session, b"discovered answer".to_vec(), at(n.now))
        .unwrap();
    n.pump(4, actions);
    assert!(
        n.events
            .iter()
            .any(|(i, e)| *i == 5
                && matches!(e,Event::Answered(s) if s.payload==b"discovered answer"))
    );
}

#[test]
fn publication_replaces_an_unreachable_coordinator() {
    let mut n = Network::new(&[true, true, true, true, false]);
    for server in 1..4 {
        let actions = n.nodes[0].1.probe(contact(server + 1), at(n.now)).unwrap();
        n.pump(0, actions);
    }
    let topic = contact(5).id;
    let actions = n.nodes[4]
        .1
        .publish(topic, &[contact(1)], at(n.now))
        .unwrap();
    n.pump(4, actions);
    let original: Vec<_> = n
        .events
        .iter()
        .filter_map(|(i, e)| match e {
            Event::Registered(r) if *i == 4 => Some(r.coordinator),
            _ => None,
        })
        .collect();
    assert_eq!(original.len(), 3);
    let failed = original[0];
    let alternate = (1..=4)
        .map(contact)
        .find(|c| !original.contains(c))
        .unwrap();
    for second in 101..=160 {
        n.now = second;
        let actions = n.nodes[4].1.tick(at(n.now));
        n.pump_with(4, actions, |from, to, _| {
            from == failed.addr || to == failed.addr
        });
    }
    assert!(n
        .events
        .iter()
        .any(|(i, e)| *i == 4 && matches!(e,Event::Registered(r) if r.coordinator==alternate)));
    assert!(n.nodes[4].1.unpublish(topic));
    assert_eq!(n.nodes[4].1.poll_timeout(), None);
    assert!(!n.nodes[4].1.unpublish(topic));
}

#[test]
fn routing_maintenance_preserves_bootstrap_discovery_after_multiple_expiry_periods() {
    let mut n = Network::new(&[true, true, true, true, false, false]);
    for server in 1..4 {
        let actions = n.nodes[0].1.probe(contact(server + 1), at(n.now)).unwrap();
        n.pump(0, actions);
    }
    let actions = n.nodes[0].1.maintain_routing(at(n.now));
    n.pump(0, actions);
    let topic = contact(5).id;
    let actions = n.nodes[4]
        .1
        .publish(topic, &[contact(1)], at(n.now))
        .unwrap();
    n.pump(4, actions);
    for _ in 0..650 {
        n.tick();
    }
    assert_eq!(n.nodes[0].1.routing_len(), 3);
    let (_, actions) = n.nodes[5]
        .1
        .lookup(topic, &[contact(1)], at(n.now))
        .unwrap();
    n.pump(5, actions);
    let records: Vec<_> = n
        .events
        .iter()
        .filter_map(|(i, e)| match e {
            Event::Providers { records, .. } if *i == 5 => Some(records.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|r| r.expires > n.now));
    let (session, actions) = n.nodes[5]
        .1
        .signal_via(&records, b"late offer".to_vec(), at(n.now))
        .unwrap();
    n.pump(5, actions);
    let actions = n.nodes[4]
        .1
        .answer(session, b"late answer".to_vec(), at(n.now))
        .unwrap();
    n.pump(4, actions);
    assert!(n
        .events
        .iter()
        .any(|(i, e)| *i == 5 && matches!(e,Event::Answered(s) if s.payload==b"late answer")));
}

#[test]
fn routing_exploration_learns_a_referral_only_after_authentication() {
    let mut n = Network::new(&[true, true, true]);
    let actions = n.nodes[1].1.probe(contact(3), at(n.now)).unwrap();
    n.pump(1, actions);
    let actions = n.nodes[0].1.probe(contact(2), at(n.now)).unwrap();
    n.pump(0, actions);
    assert_eq!(n.nodes[0].1.routing_len(), 1);
    n.events.clear();
    let actions = n.nodes[0].1.maintain_routing(at(n.now));
    n.pump(0, actions);
    n.now = 160;
    let actions = n.nodes[0].1.tick(at(n.now));
    n.pump_with(0, actions, |_, to, _| to == address(3));
    assert_eq!(
        n.nodes[0].1.routing_len(),
        1,
        "unanswered referral is not a route"
    );
    n.now = 161;
    let actions = n.nodes[0].1.tick(at(n.now));
    n.pump(0, actions);
    assert_eq!(n.nodes[0].1.routing_len(), 2);
    assert!(!n.events.iter().any(|(i, e)| *i == 0
        && matches!(
            e,
            Event::LookupDone { .. } | Event::Providers { .. } | Event::Ready(_)
        )));
}

#[test]
fn provider_pages_enumerate_a_popular_topic_and_tolerate_expiry() {
    let mut n = Network::new(&[true, false, false, false, false, false, false, false]);
    let topic = contact(90).id;
    for i in 1..7 {
        let actions = n.nodes[i].1.register(contact(1), topic, at(n.now)).unwrap();
        n.pump(i, actions);
    }
    let mut cursor = None;
    let mut providers = Vec::new();
    for page in 0..3 {
        let (request, actions) = n.nodes[7]
            .1
            .providers_page(contact(1), topic, cursor, at(n.now))
            .unwrap();
        n.pump(7, actions);
        let (records, next) = n
            .events
            .iter()
            .find_map(|(i, e)| match e {
                Event::ProviderPage {
                    request: id,
                    coordinator,
                    topic: got,
                    records,
                    next,
                } if *i == 7 && *id == request => {
                    assert_eq!(*coordinator, contact(1));
                    assert_eq!(*got, topic);
                    Some((records.clone(), *next))
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(next.is_none(), page == 2);
        providers.extend(records.iter().map(|r| dht_next::node_id(r.provider)));
        cursor = next;
    }
    let mut expected: Vec<_> = (2..8).map(|i| contact(i).id).collect();
    expected.sort();
    assert_eq!(providers, expected);
    n.now = 401;
    let (request, actions) = n.nodes[7]
        .1
        .providers_page(contact(1), topic, Some(providers[1]), at(n.now))
        .unwrap();
    n.pump(7, actions);
    assert!(n.events.iter().any(|(i, e)| *i == 7 && matches!(e, Event::ProviderPage { request: id, records, next: None, .. } if *id == request && records.is_empty())));
}

#[test]
fn signaling_rotation_preserves_live_old_records_during_grace() {
    let mut n = Network::new(&[true, false, false]);
    let topic = contact(90).id;
    let actions = n.nodes[1].1.register(contact(1), topic, at(n.now)).unwrap();
    n.pump(1, actions);
    let old = n
        .events
        .iter()
        .find_map(|(i, e)| match e {
            Event::Registered(r) if *i == 1 => Some(r.clone()),
            _ => None,
        })
        .unwrap();
    n.nodes[1].1.rotate_signaling_key(at(n.now)).unwrap();
    n.events.clear();
    let actions = n.nodes[1].1.register(contact(1), topic, at(n.now)).unwrap();
    n.pump(1, actions);
    let new = n
        .events
        .iter()
        .find_map(|(i, e)| match e {
            Event::Registered(r) if *i == 1 => Some(r.clone()),
            _ => None,
        })
        .unwrap();
    assert_ne!(old.signaling_key, new.signaling_key);
    for record in [old, new] {
        let (session, actions) = n.nodes[2]
            .1
            .signal(record, b"rotating offer".to_vec(), at(n.now))
            .unwrap();
        n.pump(2, actions);
        assert!(n.events.iter().any(|(i, e)| *i == 1 && matches!(e, Event::Incoming { signal, .. } if signal.envelope.session == session && signal.payload == b"rotating offer")));
        let actions = n.nodes[1]
            .1
            .answer(session, b"rotating answer".to_vec(), at(n.now))
            .unwrap();
        n.pump(1, actions);
        assert!(n.events.iter().any(|(i, e)| *i == 2
            && matches!(e, Event::Answered(signal) if signal.envelope.session == session)));
    }
}

#[test]
fn value_lookup_follows_referrals_to_content_and_finishes_without_a_second_get_phase() {
    let mut n = Network::new(&[true, true, true, false, false]);
    for (a, b) in [(0, 1), (1, 2)] {
        let actions = n.nodes[a].1.probe(contact(b as u8 + 1), at(n.now)).unwrap();
        n.pump(a, actions);
    }
    let value = dht_next::Value::Immutable(b"only at the end of the chain".to_vec());
    let (_, actions) = n.nodes[3]
        .1
        .put_value(contact(3), value.clone(), None, at(n.now))
        .unwrap();
    n.pump(3, actions);
    let (query, actions) = n.nodes[4]
        .1
        .lookup_value(value.key(), &[contact(1)], at(n.now))
        .unwrap();
    n.pump(4, actions);
    assert!(n.events.iter().any(|(node, event)| *node == 4 && matches!(event, Event::ValueLookupDone { query: id, result, .. } if *id == query && result.value.as_ref() == Some(&value) && result.responses == 3 && result.attempted == 3)));
    assert_eq!(n.nodes[4].1.pending_len(), 0);
}
