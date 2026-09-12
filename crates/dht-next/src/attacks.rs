fn at(seconds: u64) -> Time {
    Time::new(seconds * 1000, seconds)
}
use super::*;
use proptest::prelude::*;

fn key(n: u8) -> Keypair {
    Keypair::from_seed(&[n; 32])
}
fn addr(n: u8) -> SocketAddr {
    format!("198.51.{n}.1:4000").parse().unwrap()
}
fn contact(n: u8) -> Contact {
    Contact::new(node_id(key(n).public()), addr(n))
}
fn core(n: u8) -> Dht {
    Dht::new(key(n), [n + 100; 32], true)
}
fn packet(body: Body) -> Packet {
    Packet {
        key: key(1).public(),
        destination: contact(2).id,
        server: true,
        nonce: [42; 32],
        epoch: 0,
        cookie: [0; 32],
        body,
        exchange: Vec::new(),
    }
}
fn challenged(receiver: &mut Dht, mut p: Packet) -> Packet {
    let actions = receiver.receive(addr(1), &p.encode(&key(1)), at(100));
    let Action::Send { bytes, .. } = &actions[0] else {
        panic!()
    };
    let challenge = Packet::decode(bytes).unwrap();
    assert!(matches!(challenge.body, Body::Challenge));
    p.epoch = challenge.epoch;
    p.cookie = challenge.cookie;
    p
}

#[test]
fn stolen_cookie_cannot_be_used_from_a_different_endpoint_or_identity() {
    let mut receiver = core(2);
    let valid = challenged(&mut receiver, packet(Body::Probe));
    receiver.receive(addr(3), &valid.encode(&key(1)), at(100));
    assert_eq!(receiver.routing_len(), 0);
    let mut stolen = valid.clone();
    stolen.key = key(3).public();
    receiver.receive(addr(1), &stolen.encode(&key(3)), at(100));
    assert_eq!(receiver.routing_len(), 0);
    receiver.receive(addr(1), &valid.encode(&key(1)), at(100));
    assert_eq!(receiver.routing_len(), 1);
}

#[test]
fn forged_announcement_does_not_register_someone_elses_identity() {
    let mut receiver = core(2);
    let forged = Record::sign(&key(3), contact(3).id, contact(2), 300, [9; 32]);
    let valid = challenged(&mut receiver, packet(Body::Register(forged)));
    assert!(receiver
        .receive(addr(1), &valid.encode(&key(1)), at(100))
        .is_empty());
    assert_eq!(receiver.registration_len(), 0);
}

#[test]
fn mismatched_responses_do_not_consume_requests_or_poison_routing() {
    let mut receiver = core(2);
    let actions = receiver.probe(contact(1), at(100)).unwrap();
    let Action::Send { bytes, .. } = &actions[0] else {
        panic!()
    };
    let request = Packet::decode(bytes).unwrap();
    let mut reply = packet(Body::Ack);
    reply.nonce = request.nonce;
    receiver.receive(addr(3), &reply.encode(&key(1)), at(100));
    assert_eq!(receiver.pending_len(), 1);
    reply.body = Body::Nodes {
        contacts: vec![contact(3)],
        records: vec![],
    };
    receiver.receive(addr(1), &reply.encode(&key(1)), at(100));
    assert_eq!(receiver.pending_len(), 1);
    assert_eq!(receiver.routing_len(), 0);
    reply.body = Body::Ack;
    receiver.receive(addr(1), &reply.encode(&key(1)), at(100));
    assert_eq!(receiver.pending_len(), 0);
}

#[test]
fn replay_returns_cached_reply_without_repeating_a_forward() {
    let mut receiver = core(2);
    let record = Record::sign(&key(3), contact(3).id, contact(2), 300, [9; 32]);
    receiver.registrations.insert(
        (record.topic, contact(3).id),
        Registration {
            record: record.clone(),
            endpoint: contact(3),
        },
    );
    let signal = Signal::sign(&key(1), contact(3).id, [9; 32], 110, false, vec![1; 48]);
    let p = challenged(
        &mut receiver,
        packet(Body::Offer {
            record,
            signal: Box::new(signal),
        }),
    );
    let bytes = p.encode(&key(1));
    let actions = receiver.receive(addr(1), &bytes, at(100));
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a, Action::Send { to, .. } if *to == addr(3)))
            .count(),
        1
    );
    let replay = receiver.receive(addr(1), &bytes, at(100));
    assert_eq!(replay.len(), 1);
    assert!(matches!(&replay[0], Action::Send { to, .. } if *to == addr(1)));
    assert_eq!(receiver.exchanges.len(), 1);
}

#[test]
fn coordinator_cannot_forge_an_answer_or_redirect_the_return_path() {
    let mut receiver = core(2);
    let session = [7; 32];
    receiver.exchanges.insert(
        session,
        Exchange {
            initiator: contact(3),
            target: contact(1),
            expires: 110,
            answered: false,
        },
    );
    let redirected = Signal::sign(&key(1), contact(4).id, session, 110, true, vec![0; 48]);
    let p = challenged(&mut receiver, packet(Body::Answer(redirected)));
    assert!(receiver
        .receive(addr(1), &p.encode(&key(1)), at(100))
        .is_empty());
    assert!(!receiver.exchanges[&session].answered);
    let mut client = core(3);
    client.outgoing.insert(
        session,
        Outgoing {
            alternates: vec![],
            coordinators: vec![contact(2)],
            offer: None,
            failover_at: 110_000,
            handshake: None,
            deadline: 110_000,
            target: contact(1).id,
            expires: 110,
        },
    );
    let forged = Signal::sign(&key(2), contact(3).id, session, 110, true, vec![0; 48]);
    let mut out = vec![];
    assert!(client
        .handle_request(contact(2), &Body::Forward(forged), at(100), &mut out)
        .is_none());
    assert!(out.is_empty());
}

#[test]
fn saturated_replay_cache_rejects_new_effects_instead_of_forgetting_old_ones() {
    let mut receiver = core(2);
    let p = challenged(&mut receiver, packet(Body::Probe));
    for i in 0..MAX_REPLAYS {
        let mut nonce = [0; 32];
        nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
        receiver.replay.insert(
            (contact(1).id, nonce),
            Replay {
                expires: 120_000,
                from: addr(1),
                response: vec![],
                packet: None,
            },
        );
    }
    assert!(receiver
        .receive(addr(1), &p.encode(&key(1)), at(100))
        .is_empty());
    assert_eq!(receiver.routing_len(), 0);
}

#[test]
fn tampering_version_destination_and_trailing_bytes_are_rejected() {
    let original = packet(Body::Probe).encode(&key(1));
    for i in [0, 4, 5, 40, original.len() - 1] {
        let mut corrupt = original.clone();
        corrupt[i] ^= 1;
        assert!(Packet::decode(&corrupt).is_none());
    }
    let mut trailing = original;
    trailing.push(0);
    assert!(Packet::decode(&trailing).is_none());
    let mut wrong_destination = packet(Body::Probe);
    wrong_destination.destination = contact(3).id;
    assert!(core(2)
        .receive(addr(1), &wrong_destination.encode(&key(1)), at(100))
        .is_empty());
}

#[test]
fn maximum_ipv6_nodes_response_fits_one_datagram() {
    let mut c = contact(2);
    c.addr = "[2001:db8::1]:4000".parse().unwrap();
    let record = Record::sign(&key(1), contact(1).id, c, 300, [9; 32]);
    let mut p = packet(Body::Nodes {
        contacts: vec![c; protocol::MAX_CONTACTS],
        records: vec![record; protocol::MAX_RECORDS],
    });
    p.exchange = vec![0; 48];
    let bytes = p.encode(&key(1));
    assert!(bytes.len() <= protocol::MAX_PACKET);
    assert!(Packet::decode(&bytes).is_some());
}

proptest! {
    #[test]
    fn arbitrary_packets_never_panic_or_allocate_state(bytes in prop::collection::vec(any::<u8>(), 0..1500)) {
        let mut dht = core(2);
        let _ = dht.receive(addr(1), &bytes, at(100));
        prop_assert_eq!(dht.routing_len(), 0);
        prop_assert_eq!(dht.registration_len(), 0);
        prop_assert_eq!(dht.pending_len(), 0);
    }
}

fn pair(a: &mut Dht, b: &mut Dht, actions: Vec<Action>, time: Time) -> usize {
    let mut queue: std::collections::VecDeque<_> = actions.into_iter().map(|x| (true, x)).collect();
    let mut packets = 0;
    while let Some((from_a, action)) = queue.pop_front() {
        if let Action::Send { to, bytes } = action {
            packets += 1;
            assert!(packets < 30);
            let outputs = if from_a {
                assert_eq!(to, addr(2));
                b.receive(addr(1), &bytes, time)
            } else {
                assert_eq!(to, addr(1));
                a.receive(addr(2), &bytes, time)
            };
            queue.extend(outputs.into_iter().map(|x| (!from_a, x)));
        }
    }
    packets
}

#[test]
fn validated_peer_uses_one_round_trip_and_refreshes_after_expiry_or_restart() {
    let mut a = core(1);
    let mut b = core(2);
    let actions = a.probe(contact(2), at(100)).unwrap();
    assert_eq!(pair(&mut a, &mut b, actions, at(100)), 4);
    assert!(a.transport.available(contact(2).id, addr(2), at(101)));
    let actions = a.probe(contact(2), at(101)).unwrap();
    assert_eq!(pair(&mut a, &mut b, actions, at(101)), 2);
    let actions = a.probe(contact(2), at(131)).unwrap();
    assert_eq!(pair(&mut a, &mut b, actions, at(131)), 4);
    let mut restarted = Dht::new(key(2), [99; 32], true);
    let actions = a.probe(contact(2), at(132)).unwrap();
    assert_eq!(pair(&mut a, &mut restarted, actions, at(132)), 1);
    let retry = a.tick(Time::new(132_200, 132));
    assert_eq!(
        pair(&mut a, &mut restarted, retry, Time::new(132_200, 132)),
        1
    );
    let retry = a.tick(Time::new(132_600, 132));
    assert_eq!(
        pair(&mut a, &mut restarted, retry, Time::new(132_600, 132)),
        4
    );
    assert_eq!(a.pending_len(), 0);
    assert!(a.transport.available(contact(2).id, addr(2), at(133)));
}

#[test]
fn reused_grant_still_requires_the_owners_signature_for_every_new_request() {
    let mut receiver = core(2);
    let valid = challenged(&mut receiver, packet(Body::Probe));
    receiver.receive(addr(1), &valid.encode(&key(1)), at(100));
    let mut fresh = valid.clone();
    fresh.nonce = [43; 32];
    assert!(receiver
        .receive(addr(1), &fresh.encode(&key(3)), at(100))
        .is_empty());
    let result = receiver.receive(addr(1), &fresh.encode(&key(1)), at(100));
    assert_eq!(result.len(), 1);
    let Action::Send { bytes, .. } = &result[0] else {
        panic!()
    };
    assert!(matches!(Packet::decode(bytes).unwrap().body, Body::Ack));
}

#[test]
fn monotonic_deadlines_and_rate_limits_ignore_wall_clock_jumps() {
    let mut d = core(2);
    d.probe(contact(1), Time::new(100_000, 100)).unwrap();
    assert_eq!(d.poll_timeout(), Some(100_500));
    assert!(d.tick(Time::new(100_100, 9000)).is_empty());
    assert_eq!(d.pending_len(), 1);
    d.tick(Time::new(109_000, 1));
    assert_eq!(d.pending_len(), 0);
    assert_eq!(d.poll_timeout(), None);
    for _ in 0..256 {
        d.receive(addr(1), &[0], Time::new(110_000, 100));
    }
    assert!(d
        .receive(
            addr(1),
            &packet(Body::Probe).encode(&key(1)),
            Time::new(110_000, 9000)
        )
        .is_empty());
}

#[test]
fn hedged_queries_respect_the_hard_concurrency_cap() {
    let mut d = core(2);
    let seeds: Vec<_> = (3..20).map(contact).collect();
    d.lookup(contact(1).id, &seeds, at(100)).unwrap();
    assert_eq!(d.pending_len(), ALPHA);
    d.tick(Time::new(100_500, 100));
    assert_eq!(d.pending_len(), MAX_FLIGHT);
    for ms in (100_510..103_000).step_by(10) {
        d.tick(Time::new(ms, 100));
        assert!(d.pending_len() <= MAX_FLIGHT);
    }
}

fn sent(actions: &[Action]) -> Vec<u8> {
    actions
        .iter()
        .find_map(|a| match a {
            Action::Send { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .expect("a datagram")
}

#[test]
fn lost_encrypted_reply_recovers_with_fresh_counters_and_one_registration_effect() {
    let mut a = core(1);
    let mut b = core(2);
    let initial = a.probe(contact(2), at(100)).unwrap();
    pair(&mut a, &mut b, initial, at(100));
    let request = sent(&a.register(contact(2), contact(1).id, at(101)).unwrap());
    assert!(Packet::decode(&request).is_none());
    let lost = sent(&b.receive(addr(1), &request, at(101)));
    assert_eq!(b.registration_len(), 1);
    assert_eq!(b.replay.len(), 2);
    assert!(b.receive(addr(1), &request, at(101)).is_empty());
    let retry = sent(&a.tick(Time::new(101_200, 101)));
    assert_ne!(request, retry);
    let reply = sent(&b.receive(addr(1), &retry, Time::new(101_200, 101)));
    assert_ne!(lost, reply);
    assert_eq!(b.registration_len(), 1);
    assert_eq!(b.replay.len(), 2);
    let events = a.receive(addr(2), &reply, Time::new(101_200, 101));
    assert!(events
        .iter()
        .any(|a| matches!(a, Action::Event(e) if matches!(**e, Event::Registered(_)))));
    assert_eq!(a.pending_len(), 0);
    assert!(a
        .receive(addr(2), &lost, Time::new(101_201, 101))
        .is_empty());
}

#[test]
fn lost_handshake_reply_reuses_exact_exchange_and_then_enables_encryption() {
    let mut a = core(1);
    let mut b = core(2);
    let opener = sent(&a.probe(contact(2), at(100)).unwrap());
    let challenge = sent(&b.receive(addr(1), &opener, at(100)));
    assert!(!b.transport.available(contact(1).id, addr(1), at(100)));
    let validated = sent(&a.receive(addr(2), &challenge, at(100)));
    let lost = sent(&b.receive(addr(1), &validated, at(100)));
    assert_eq!(Packet::decode(&lost).unwrap().exchange.len(), 48);
    let retry = sent(&a.tick(Time::new(100_200, 100)));
    assert_eq!(retry, validated);
    let recovered = sent(&b.receive(addr(1), &retry, Time::new(100_200, 100)));
    assert_eq!(lost, recovered);
    a.receive(addr(2), &recovered, Time::new(100_200, 100));
    assert!(a.transport.available(contact(2).id, addr(2), at(101)));
    assert_eq!(a.pending_len(), 0);
}

#[test]
fn encrypted_signaling_rejects_corruption_and_retries_an_answer_after_capacity_failure() {
    let mut provider = core(1);
    let mut coordinator = core(2);
    let actions = provider
        .register(contact(2), contact(1).id, at(100))
        .unwrap();
    pair(&mut provider, &mut coordinator, actions, at(100));
    let record = provider
        .authorizations
        .values()
        .next()
        .unwrap()
        .record
        .clone();
    let mut caller = core(3);
    let offer_plain = b"private offer candidates".to_vec();
    let (session, packets) = caller.signal(record, offer_plain.clone(), at(101)).unwrap();
    assert!(!sent(&packets)
        .windows(offer_plain.len())
        .any(|w| w == offer_plain));
    let signal = caller
        .pending
        .values()
        .find_map(|p| match &p.packet.body {
            Body::Offer { signal, .. } => Some(signal.as_ref().clone()),
            _ => None,
        })
        .unwrap();
    let mut bad = signal.payload.clone();
    bad[40] ^= 1;
    let corrupted = Signal::sign(&key(3), contact(1).id, session, signal.expires, false, bad);
    let mut out = Vec::new();
    assert!(provider
        .handle_request(contact(2), &Body::Forward(corrupted), at(101), &mut out)
        .is_none());
    assert!(provider.incoming.is_empty());
    assert!(out.is_empty());
    assert_eq!(
        provider.handle_request(contact(2), &Body::Forward(signal), at(101), &mut out),
        Some(Body::Ack)
    );
    assert!(out.iter().any(|a| matches!(a, Action::Event(e) if matches!(e.as_ref(),
        Event::Incoming { signal, .. } if signal.payload == offer_plain && signal.envelope.verify(101)))));
    for _ in 0..MAX_PENDING {
        provider.probe(contact(2), at(101)).unwrap();
    }
    let answer_plain = b"private answer candidates".to_vec();
    assert_eq!(
        provider.answer(session, answer_plain.clone(), at(101)),
        Err(Error::Capacity)
    );
    assert!(!provider.incoming[&session].answered);
    provider.pending.pop_first();

    provider
        .answer(session, answer_plain.clone(), at(101))
        .unwrap();
    let answer = provider
        .pending
        .values()
        .find_map(|p| match &p.packet.body {
            Body::Answer(signal) => Some(signal.clone()),
            _ => None,
        })
        .unwrap();
    assert!(!answer
        .payload
        .windows(answer_plain.len())
        .any(|w| w == answer_plain));
    let mut events = vec![];
    assert_eq!(
        caller.handle_request(contact(2), &Body::Forward(answer), at(101), &mut events),
        Some(Body::Ack)
    );
    assert!(
        events
            .iter()
            .any(|a| matches!(a, Action::Event(e) if matches!(e.as_ref(),
        Event::Answered(signal) if signal.payload == answer_plain && signal.envelope.verify(101))))
    );
}

#[test]
fn failover_inputs_and_deadlines_are_bounded() {
    let mut d = core(1);
    let record = Record::sign(&key(3), contact(3).id, contact(2), 300, [9; 32]);
    assert_eq!(d.signal_via(&[], vec![], at(100)), Err(Error::Invalid));
    assert_eq!(
        d.signal_via(&[record.clone(), record.clone()], vec![], at(100)),
        Err(Error::Invalid)
    );
    let other = Record::sign(&key(3), contact(3).id, contact(4), 300, [8; 32]);
    assert_eq!(
        d.signal_via(&[record.clone(), other], vec![], at(100)),
        Err(Error::Invalid)
    );
    let other = Record::sign(&key(4), contact(3).id, contact(4), 300, [9; 32]);
    assert_eq!(
        d.signal_via(&[record.clone(), other], vec![], at(100)),
        Err(Error::Invalid)
    );
    let second = Record::sign(&key(3), contact(3).id, contact(4), 300, [9; 32]);
    let third = Record::sign(&key(3), contact(3).id, contact(5), 300, [9; 32]);
    let (session, _) = d
        .signal_via(&[record, second, third], vec![], at(100))
        .unwrap();
    d.tick(at(102));
    assert_eq!(d.outgoing[&session].coordinators.len(), 2);
    d.tick(at(104));
    assert_eq!(d.outgoing[&session].coordinators.len(), 3);
    assert!(d.outgoing[&session].alternates.is_empty());
    let actions = d.tick(at(120));
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a,Action::Event(e) if **e == Event::SignalTimedOut(session)))
            .count(),
        1
    );
    assert!(d.outgoing.is_empty());
    assert!(d.pending.is_empty());
    assert!(!d
        .tick(at(121))
        .iter()
        .any(|a| matches!(a,Action::Event(e) if matches!(**e,Event::SignalTimedOut(_)))));
}

#[test]
fn full_registration_table_can_renew_existing_slots_without_downgrading_a_lease() {
    let mut provider = core(1);
    let mut coordinator = core(2);
    let actions = provider
        .maintain_registration(contact(2), contact(1).id, at(100))
        .unwrap();
    pair(&mut provider, &mut coordinator, actions, at(100));
    let template = provider
        .authorizations
        .values()
        .next()
        .unwrap()
        .record
        .clone();
    for i in 0..MAX_REGISTRATIONS - 1 {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let topic = NodeId::from_bytes(bytes);
        provider.authorizations.insert(
            (topic, contact(2).id),
            Registration {
                record: Record::sign(&key(1), topic, contact(2), 400, template.signaling_key),
                endpoint: contact(2),
            },
        );
    }
    assert_eq!(provider.authorizations.len(), MAX_REGISTRATIONS);
    assert_eq!(
        provider.register(contact(3), contact(1).id, at(101)),
        Err(Error::Capacity)
    );
    let actions = provider
        .register(contact(2), contact(1).id, at(110))
        .unwrap();
    pair(&mut provider, &mut coordinator, actions, at(110));
    assert_eq!(
        provider.authorizations[&(contact(1).id, contact(2).id)]
            .record
            .expires,
        410
    );
    assert_eq!(provider.authorizations.len(), MAX_REGISTRATIONS);
    let older = sent(
        &provider
            .register(contact(2), contact(1).id, at(111))
            .unwrap(),
    );
    let older_ack = sent(&coordinator.receive(addr(1), &older, at(111)));
    let newer = sent(
        &provider
            .register(contact(2), contact(1).id, at(112))
            .unwrap(),
    );
    let newer_ack = sent(&coordinator.receive(addr(1), &newer, at(112)));
    provider.receive(addr(2), &newer_ack, at(112));
    assert!(provider.receive(addr(2), &older_ack, at(112)).is_empty());
    assert_eq!(
        provider.authorizations[&(contact(1).id, contact(2).id)]
            .record
            .expires,
        412
    );
}

#[test]
fn stopping_a_pending_managed_registration_ignores_its_late_ack() {
    let mut provider = core(1);
    let mut coordinator = core(2);
    let opener = sent(
        &provider
            .maintain_registration(contact(2), contact(1).id, at(100))
            .unwrap(),
    );
    let challenge = sent(&coordinator.receive(addr(1), &opener, at(100)));
    let validated = sent(&provider.receive(addr(2), &challenge, at(100)));
    let ack = sent(&coordinator.receive(addr(1), &validated, at(100)));
    assert!(provider.stop_renewing(contact(1).id, contact(2).id));
    assert!(provider.receive(addr(2), &ack, at(100)).is_empty());
    assert!(provider.authorizations.is_empty());
    assert!(provider.managed.is_empty());
    assert_eq!(provider.poll_timeout(), None);
    assert!(!provider.stop_renewing(contact(1).id, contact(2).id));
}

#[test]
fn expired_registration_ack_keeps_a_timer_and_does_not_claim_success() {
    let mut provider = core(1);
    let mut coordinator = core(2);
    let opener = sent(
        &provider
            .maintain_registration(contact(2), contact(1).id, at(100))
            .unwrap(),
    );
    let challenge = sent(&coordinator.receive(addr(1), &opener, at(100)));
    let validated = sent(&provider.receive(addr(2), &challenge, at(100)));
    let ack = sent(&coordinator.receive(addr(1), &validated, at(100)));
    assert!(provider
        .receive(addr(2), &ack, Time::new(100_100, 500))
        .is_empty());
    assert!(provider.authorizations.is_empty());
    assert!(provider.poll_timeout().is_some());
    provider.tick(Time::new(110_000, 500));
    assert!(provider.managed.values().next().unwrap().pending.is_none());
    assert!(provider.poll_timeout().unwrap() > 110_000);
}

#[test]
fn managed_renewal_defers_capacity_and_ignores_backward_wall_clock_for_scheduling() {
    let mut provider = core(1);
    let mut coordinator = core(2);
    let actions = provider
        .maintain_registration(contact(2), contact(1).id, at(100))
        .unwrap();
    pair(&mut provider, &mut coordinator, actions, at(100));
    let due = provider.managed[&(contact(1).id, contact(2).id)].next_at;
    assert!(provider.tick(Time::new(due - 1, 1)).is_empty());
    assert_eq!(provider.poll_timeout(), Some(due));
    for _ in 0..MAX_PENDING {
        provider.probe(contact(2), Time::new(due, 300)).unwrap();
    }
    provider.tick(Time::new(due, 300));
    let m = &provider.managed[&(contact(1).id, contact(2).id)];
    assert!(m.pending.is_none());
    assert_eq!(m.next_at, due + 1000);
    provider.pending.clear();
    let actions = provider.tick(Time::new(due + 1000, 301));
    assert_eq!(actions.len(), 1);
    assert!(provider.managed[&(contact(1).id, contact(2).id)]
        .pending
        .is_some());
    pair(
        &mut provider,
        &mut coordinator,
        actions,
        Time::new(due + 1000, 301),
    );
    assert_eq!(
        provider.authorizations[&(contact(1).id, contact(2).id)]
            .record
            .expires,
        601
    );
}

#[test]
fn publication_bounds_empty_bootstrap_retries_and_cancel_pending_discovery() {
    let mut d = core(1);
    let topic = contact(3).id;
    assert!(d.publish(topic, &[], at(100)).unwrap().is_empty());
    assert_eq!(d.poll_timeout(), Some(102_000));
    assert!(d.tick(at(102)).is_empty());
    assert_eq!(d.poll_timeout(), Some(106_000));
    let actions = d.publish(topic, &[contact(2)], at(103)).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(d.queries.len(), 1);
    assert_eq!(d.pending_len(), 1);
    assert!(d.unpublish(topic));
    assert!(d.queries.is_empty());
    assert_eq!(d.pending_len(), 0);
    assert_eq!(d.poll_timeout(), None);
    for i in 0..MAX_PUBLICATIONS {
        let mut bytes = [0; 32];
        bytes[0] = i as u8;
        d.publish(NodeId::from_bytes(bytes), &[], at(104)).unwrap();
    }
    assert_eq!(d.publish(topic, &[], at(104)), Err(Error::Capacity));
    assert_eq!(
        d.publish(topic, &[contact(2); 9], at(104)),
        Err(Error::Invalid)
    );
}

#[test]
fn publication_does_not_adopt_or_stop_manual_renewals() {
    let mut d = core(1);
    let mut server = core(2);
    let topic = contact(3).id;
    let actions = d.maintain_registration(contact(2), topic, at(100)).unwrap();
    pair(&mut d, &mut server, actions, at(100));
    let actions = d.publish(topic, &[contact(2)], at(100)).unwrap();
    pair(&mut d, &mut server, actions, at(100));
    assert!(d.unpublish(topic));
    assert!(d.managed.contains_key(&(topic, contact(2).id)));
    assert!(d.poll_timeout().unwrap() > 100_000);
}

#[test]
fn publication_query_capacity_failure_keeps_a_future_retry() {
    let mut d = core(1);
    for _ in 0..MAX_QUERIES {
        d.lookup(contact(3).id, &[contact(2)], at(100)).unwrap();
    }
    assert!(d
        .publish(contact(4).id, &[contact(2)], at(100))
        .unwrap()
        .is_empty());
    assert_eq!(d.publications[&contact(4).id].next_at, 105_000);
    assert_eq!(d.queries.len(), MAX_QUERIES);
    assert!(d.unpublish(contact(4).id));
    assert_eq!(d.queries.len(), MAX_QUERIES);
}

#[test]
fn manual_takeover_of_an_automatic_lease_survives_unpublish() {
    let mut d = core(1);
    let mut server = core(2);
    let topic = contact(3).id;
    let actions = d.publish(topic, &[contact(2)], at(100)).unwrap();
    pair(&mut d, &mut server, actions, at(100));
    assert_eq!(d.managed[&(topic, contact(2).id)].publication, Some(topic));
    assert!(d
        .maintain_registration(contact(2), topic, at(100))
        .unwrap()
        .is_empty());
    assert!(d.unpublish(topic));
    assert!(d.managed.contains_key(&(topic, contact(2).id)));
    assert!(d.managed[&(topic, contact(2).id)].publication.is_none());
}

fn lookup_candidate(n: u16, address: &str) -> Contact {
    let mut id = [0; 32];
    id[30..].copy_from_slice(&n.to_be_bytes());
    Contact::new(NodeId::from_bytes(id), address.parse().unwrap())
}

#[test]
fn initial_lookup_filters_prefix_flood_before_selecting_closest_candidates() {
    let mut d = core(2);
    let mut seeds: Vec<_> = (1..=64)
        .rev()
        .map(|n| lookup_candidate(n, &format!("203.0.113.{n}:4000")))
        .collect();
    seeds.push(contact(3));
    let (id, actions) = d
        .lookup(NodeId::from_bytes([0; 32]), &seeds, at(100))
        .unwrap();
    let query = &d.queries[&id];
    assert_eq!(query.contacts.len(), 9);
    for c in [seeds[63], seeds[62], seeds[61]] {
        assert!(query.contacts.contains_key(&c.id));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Send { to, .. } if *to == c.addr)));
    }
    assert_eq!(d.routing_len(), 0);
}

#[test]
fn lookup_candidate_aliases_and_invalid_addresses_cannot_consume_extra_slots() {
    let mut d = core(2);
    let seeds: Vec<_> = [
        "0.0.0.0:4000",
        "224.0.0.1:4000",
        "192.0.2.1:0",
        "192.0.2.1:4000",
        "192.0.2.1:4001",
        "[::ffff:192.0.2.1]:4000",
        "[::ffff:192.0.2.2]:4000",
        "192.0.2.3:4000",
        "[2001:db8:1:1::1]:4000",
        "[2001:db8:1:1::2]:4000",
        "[2001:db8:1:1::3]:4000",
        "[2001:db8:1:2::1]:4000",
    ]
    .iter()
    .enumerate()
    .map(|(i, addr)| lookup_candidate(i as u16 + 1, addr))
    .collect();
    let (id, _) = d
        .lookup(NodeId::from_bytes([0; 32]), &seeds, at(100))
        .unwrap();
    assert_eq!(d.queries[&id].contacts.len(), 7);
    for i in [3, 6, 7, 8, 9, 10, 11] {
        assert!(d.queries[&id].contacts.contains_key(&seeds[i].id));
    }
}

#[test]
fn failed_candidates_keep_prefix_budget_without_blocking_other_networks() {
    let mut d = core(2);
    let local = d.id();
    let seeds: Vec<_> = (1..=8)
        .map(|n| lookup_candidate(n, &format!("203.0.113.{n}:4000")))
        .collect();
    let (id, _) = d
        .lookup(NodeId::from_bytes([0; 32]), &seeds, at(100))
        .unwrap();
    let query = d.queries.get_mut(&id).unwrap();
    for candidate in query.contacts.values_mut() {
        candidate.status = Status::Failed;
    }
    query.add_candidates(
        local,
        RoutingPolicy::Diverse,
        None,
        [
            lookup_candidate(9, "203.0.113.9:4000"),
            Contact::new(seeds[0].id, "198.51.100.1:4000".parse().unwrap()),
            contact(3),
        ],
    );
    assert_eq!(query.contacts.len(), 9);
    assert!(query.contacts[&seeds[0].id].status == Status::Failed);
    assert_eq!(query.contacts[&seeds[0].id].contact, seeds[0]);
    assert!(query.contacts.contains_key(&contact(3).id));
    let (other, _) = d.lookup(contact(3).id, &seeds, at(100)).unwrap();
    assert_eq!(d.queries[&other].contacts.len(), 8, "budgets are per query");
}

#[test]
fn signed_referral_flood_still_reaches_an_independent_live_peer() {
    let mut d = core(2);
    let (id, actions) = d
        .lookup(
            NodeId::from_bytes([0; 32]),
            &[contact(1), contact(3)],
            at(100),
        )
        .unwrap();
    let opener = Packet::decode(&sent(&actions)).unwrap();
    let contacts: Vec<_> = (1..=8)
        .map(|n| lookup_candidate(n, &format!("198.51.1.{}:4000", n + 1)))
        .collect();

    let mut reply = packet(Body::Nodes {
        contacts,
        records: vec![],
    });
    reply.nonce = opener.nonce;
    d.receive(addr(1), &reply.encode(&key(1)), at(100));
    assert_eq!(d.queries[&id].contacts.len(), 9);
    assert_eq!(d.routing_len(), 1, "referrals have not authenticated");
    let to_live = actions
        .iter()
        .find_map(|a| match a {
            Action::Send { to, bytes } if *to == addr(3) => Some(bytes.clone()),
            _ => None,
        })
        .expect("independent peer queried despite nearer malicious referrals");
    let mut live = core(3);
    let challenge = sent(&live.receive(addr(2), &to_live, at(100)));
    let request = sent(&d.receive(addr(3), &challenge, at(100)));
    let response = sent(&live.receive(addr(2), &request, at(100)));
    d.receive(addr(3), &response, at(100));
    let mut events = Vec::new();
    for now in [110, 120, 130, 140] {
        events.extend(d.tick(at(now)));
    }
    assert!(events.iter().any(|a| matches!(a, Action::Event(e) if matches!(&**e,
        Event::LookupDone { query, closest, timed_out: false } if *query == id && closest.contains(&contact(3))))));
    assert_eq!(d.pending_len(), 0);
}

#[test]
fn unrestricted_lookup_preserves_concentrated_benchmarks_and_candidate_cap() {
    let mut d = Dht::with_routing_policy(key(2), [102; 32], true, RoutingPolicy::Unrestricted);
    let local = d.id();
    let seeds: Vec<_> = (1..=128)
        .map(|n| lookup_candidate(n, &format!("127.0.0.1:{}", 4000 + n)))
        .collect();
    let (id, _) = d
        .lookup(NodeId::from_bytes([0; 32]), &seeds, at(100))
        .unwrap();
    let query = d.queries.get_mut(&id).unwrap();
    assert_eq!(query.contacts.len(), MAX_CANDIDATES);
    query.add_candidates(local, RoutingPolicy::Unrestricted, None, [contact(3)]);
    assert_eq!(query.contacts.len(), MAX_CANDIDATES);
    assert!(!query.contacts.contains_key(&contact(3).id));
}

#[test]
fn authenticated_referral_chains_cannot_launder_a_seeds_candidate_budget() {
    let mut d = core(2);
    let (query, _) = d
        .lookup(
            NodeId::from_bytes([0; 32]),
            &[contact(3), contact(100)],
            at(100),
        )
        .unwrap();
    let mut replies = 0;
    loop {
        let next = d.pending.iter().find_map(|(nonce, p)| {
            (p.query == Some(query))
                .then(|| {
                    (3..100)
                        .find(|n| p.contact == contact(*n))
                        .map(|n| (*nonce, n))
                })
                .flatten()
        });
        let Some((nonce, n)) = next else { break };
        let mut reply = packet(Body::Nodes {
            contacts: (4..100)
                .map(contact)
                .filter(|c| !d.queries[&query].contacts.contains_key(&c.id))
                .take(8)
                .collect(),
            records: vec![],
        });
        reply.key = key(n).public();
        reply.nonce = nonce;
        d.receive(addr(n), &reply.encode(&key(n)), at(100));
        replies += 1;
        assert!(replies <= MAX_CANDIDATES_PER_ORIGIN);
        let q = &d.queries[&query];
        assert!(
            q.contacts
                .keys()
                .filter(|id| q.origin(**id) == contact(3).id)
                .count()
                <= MAX_CANDIDATES_PER_ORIGIN
        );
    }
    assert!(replies > protocol::MAX_CONTACTS);
    let q = &d.queries[&query];
    assert_eq!(q.contacts.len(), MAX_CANDIDATES_PER_ORIGIN + 1);
    assert!(q
        .contacts
        .values()
        .any(|c| c.referrer.is_some_and(|parent| parent != contact(3).id)));
    let nonce = *d
        .pending
        .iter()
        .find(|(_, p)| p.query == Some(query) && p.contact == contact(100))
        .unwrap()
        .0;
    let record = Record::sign(
        &key(101),
        NodeId::from_bytes([0; 32]),
        contact(100),
        300,
        [9; 32],
    );
    let mut reply = packet(Body::Nodes {
        contacts: vec![],
        records: vec![record.clone()],
    });
    reply.key = key(100).public();
    reply.nonce = nonce;
    let actions = d.receive(addr(100), &reply.encode(&key(100)), at(100));
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::Event(e) if matches!(&**e,
        Event::LookupDone { query: id, timed_out: false, .. } if *id == query))));
    assert!(actions.iter().any(|a| matches!(a, Action::Event(e) if matches!(&**e, Event::Providers { records, .. } if records.contains(&record)))));
    assert_eq!(d.pending_len(), 0);
}

#[test]
fn failed_descendants_keep_origin_budget_and_duplicates_cannot_reparent() {
    let mut d = core(2);
    let local = d.id();
    let (id, _) = d
        .lookup(
            NodeId::from_bytes([0; 32]),
            &[contact(3), contact(100)],
            at(100),
        )
        .unwrap();
    let q = d.queries.get_mut(&id).unwrap();
    q.contacts.get_mut(&contact(3).id).unwrap().status = Status::Done;
    q.contacts.get_mut(&contact(100).id).unwrap().status = Status::Done;
    q.add_candidates(
        local,
        RoutingPolicy::Diverse,
        Some(contact(3).id),
        (4..(3 + MAX_CANDIDATES_PER_ORIGIN as u8)).map(contact),
    );
    assert_eq!(q.contacts.len(), MAX_CANDIDATES_PER_ORIGIN + 1);
    for n in 4..(3 + MAX_CANDIDATES_PER_ORIGIN as u8) {
        q.contacts.get_mut(&contact(n).id).unwrap().status = Status::Failed;
    }
    q.add_candidates(
        local,
        RoutingPolicy::Diverse,
        Some(contact(3).id),
        [contact(89)],
    );
    assert!(!q.contacts.contains_key(&contact(89).id));
    q.add_candidates(
        local,
        RoutingPolicy::Diverse,
        Some(contact(100).id),
        [contact(4), contact(89)],
    );
    assert_eq!(q.origin(contact(4).id), contact(3).id);
    assert!(q.contacts[&contact(4).id].status == Status::Failed);
    assert_eq!(q.origin(contact(89).id), contact(100).id);
    q.contacts.get_mut(&contact(89).id).unwrap().status = Status::Done;
    q.add_candidates(
        local,
        RoutingPolicy::Diverse,
        Some(contact(89).id),
        [contact(100)],
    );
    assert_eq!(
        q.contacts[&contact(100).id].referrer,
        None,
        "no ancestry cycle"
    );
    let count = q.contacts.len();
    q.add_candidates(
        local,
        RoutingPolicy::Diverse,
        Some(contact(90).id),
        [contact(91)],
    );
    q.add_candidates(
        local,
        RoutingPolicy::Diverse,
        Some(contact(4).id),
        [contact(92)],
    );
    assert_eq!(
        q.contacts.len(),
        count,
        "only completed candidates can introduce referrals"
    );
}

#[test]
fn lookup_scheduling_balances_origins_then_uses_xor_distance() {
    let mut d = core(2);
    let local = d.id();
    let roots = [contact(100), contact(101), contact(102)];
    let (id, _) = d
        .lookup(NodeId::from_bytes([0; 32]), &roots, at(100))
        .unwrap();
    let q = d.queries.get_mut(&id).unwrap();
    let candidates: Vec<_> = (1..=9)
        .map(|n| lookup_candidate(n, &format!("203.0.{n}.1:4000")))
        .collect();
    for (i, root) in roots.iter().enumerate() {
        q.contacts.get_mut(&root.id).unwrap().status = Status::Done;
        q.add_candidates(
            local,
            RoutingPolicy::Diverse,
            Some(root.id),
            candidates[i * 3..i * 3 + 3].iter().copied(),
        );
    }
    assert_eq!(
        q.select_candidates(candidates.clone(), 3, RoutingPolicy::Diverse),
        vec![candidates[0], candidates[3], candidates[6]]
    );
    assert_eq!(
        q.select_candidates(candidates.clone(), 3, RoutingPolicy::Unrestricted),
        candidates[..3]
    );
    q.contacts.get_mut(&candidates[0].id).unwrap().status = Status::Flight;
    assert_eq!(
        q.select_candidates(candidates[1..].to_vec(), 3, RoutingPolicy::Diverse),
        vec![candidates[3], candidates[6], candidates[1]]
    );
    assert_eq!(
        q.select_candidates(candidates[1..3].to_vec(), 6, RoutingPolicy::Diverse),
        candidates[1..3],
        "a single available chain can use spare slots"
    );
}

#[test]
fn unrestricted_lookups_keep_referral_provenance_without_origin_quota() {
    let mut d = Dht::with_routing_policy(key(2), [102; 32], true, RoutingPolicy::Unrestricted);
    let local = d.id();
    let (id, _) = d
        .lookup(NodeId::from_bytes([0; 32]), &[contact(3)], at(100))
        .unwrap();
    let q = d.queries.get_mut(&id).unwrap();
    q.contacts.get_mut(&contact(3).id).unwrap().status = Status::Done;
    q.add_candidates(
        local,
        RoutingPolicy::Unrestricted,
        Some(contact(3).id),
        (4..40).map(contact),
    );
    assert_eq!(q.contacts.len(), 37);
    assert!(q.contacts.keys().all(|id| q.origin(*id) == contact(3).id));
}

#[test]
fn one_prefix_cannot_exhaust_global_packet_budget() {
    let mut d = core(2);
    for port in 4000..5000 {
        let from = format!("[::ffff:203.0.113.1]:{port}").parse().unwrap();
        assert!(d.receive(from, &[0], at(100)).is_empty());
    }
    assert_eq!(d.budget_used, 64);
    assert_eq!(d.budget_prefixes.len(), 1);
    let blocked = "203.0.113.2:4000".parse().unwrap();
    assert!(d
        .receive(blocked, &packet(Body::Probe).encode(&key(1)), at(100))
        .is_empty());
    assert_eq!(
        d.receive(addr(1), &packet(Body::Probe).encode(&key(1)), at(100))
            .len(),
        1
    );
    assert_eq!(d.budget_used, 65);
    assert!(d
        .receive(blocked, &packet(Body::Probe).encode(&key(1)), at(99))
        .is_empty());
    assert_eq!(
        d.receive(blocked, &packet(Body::Probe).encode(&key(1)), at(101))
            .len(),
        1
    );
    assert_eq!(d.budget_used, 1);
}

#[test]
fn many_prefixes_cannot_grow_ingress_accounting_past_global_budget() {
    let mut d = core(2);
    for n in 0..1024 {
        let from = SocketAddr::from(([10, (n / 256) as u8, (n % 256) as u8, 1], 4000));
        d.receive(from, &[0], at(100));
    }
    assert_eq!(d.budget_used, 256);
    assert_eq!(d.budget_prefixes.len(), 256);
    d.receive(addr(1), &[0], at(101));
    assert_eq!(d.budget_prefixes.len(), 1);
}

#[test]
fn closer_referrals_replace_only_unqueried_candidates() {
    let mut d = core(2);
    let local = d.id();
    let (id, _) = d
        .lookup(NodeId::from_bytes([0; 32]), &[contact(100)], at(100))
        .unwrap();
    let q = d.queries.get_mut(&id).unwrap();
    q.contacts.get_mut(&contact(100).id).unwrap().status = Status::Done;
    let far: Vec<_> = (1000..1008)
        .map(|n| lookup_candidate(n, &format!("203.0.113.{}:4000", n - 999)))
        .collect();
    q.add_candidates(
        local,
        RoutingPolicy::Diverse,
        Some(contact(100).id),
        far.iter().copied(),
    );
    q.contacts.get_mut(&far[0].id).unwrap().status = Status::Flight;
    q.contacts.get_mut(&far[1].id).unwrap().status = Status::Failed;
    let close = lookup_candidate(1, "203.0.113.99:4000");
    q.add_candidates(
        local,
        RoutingPolicy::Diverse,
        Some(contact(100).id),
        [close],
    );
    assert_eq!(q.contacts.len(), 9);
    assert!(q.contacts.contains_key(&close.id));
    assert!(!q.contacts.contains_key(&far[7].id));
    assert!(q.contacts[&far[0].id].status == Status::Flight);
    assert!(q.contacts[&far[1].id].status == Status::Failed);
    assert_eq!(q.origin(close.id), contact(100).id);
}

#[test]
fn provider_pages_validate_signatures_scope_order_and_cursor_before_completion() {
    let mut d = core(2);
    let topic = contact(90).id;
    let (nonce, _) = d.providers_page(contact(1), topic, None, at(100)).unwrap();
    let valid = Record::sign(&key(3), topic, contact(1), 300, [9; 32]);
    let wrong_topic = Record::sign(&key(3), contact(91).id, contact(1), 300, [9; 32]);
    let wrong_coordinator = Record::sign(&key(3), topic, contact(4), 300, [9; 32]);
    let mut forged = valid.clone();
    forged.expires += 1;
    for (records, next) in [
        (vec![wrong_topic], None),
        (vec![wrong_coordinator], None),
        (vec![forged], None),
        (vec![valid.clone(), valid.clone()], None),
        (vec![], Some(contact(3).id)),
        (vec![valid.clone()], Some(contact(4).id)),
    ] {
        let mut reply = packet(Body::ProviderPage { records, next });
        reply.nonce = nonce;
        assert!(d
            .receive(addr(1), &reply.encode(&key(1)), at(100))
            .is_empty());
        assert_eq!(d.pending_len(), 1);
    }
    let mut reply = packet(Body::ProviderPage {
        records: vec![valid.clone()],
        next: Some(contact(3).id),
    });
    reply.nonce = nonce;
    let events = d.receive(addr(1), &reply.encode(&key(1)), at(100));
    assert!(events.iter().any(|a| matches!(a, Action::Event(e) if matches!(&**e, Event::ProviderPage { request, records, .. } if *request == nonce && records == std::slice::from_ref(&valid)))));
    let (nonce, _) = d
        .providers_page(contact(1), topic, Some(contact(3).id), at(100))
        .unwrap();
    reply.nonce = nonce;
    assert!(
        d.receive(addr(1), &reply.encode(&key(1)), at(100))
            .is_empty(),
        "cursor cannot repeat a provider"
    );
    assert_eq!(d.pending_len(), 1);
}

#[test]
fn pagination_wire_bounds_and_version_are_strict() {
    let coordinator = Contact::new(contact(1).id, "[2001:db8::1]:4000".parse().unwrap());
    let records: Vec<_> = (3..5)
        .map(|n| Record::sign(&key(n), contact(90).id, coordinator, 300, [9; 32]))
        .collect();
    let mut page = packet(Body::ProviderPage {
        records: records.clone(),
        next: Some(contact(4).id),
    });
    page.exchange = vec![1; 48];
    let encoded = page.encode(&key(1));
    assert!(encoded.len() <= protocol::MAX_PACKET);
    assert_eq!(Packet::decode(&encoded).unwrap().body, page.body);
    page.body = Body::ProviderPage {
        records: vec![records[0].clone(); 3],
        next: None,
    };
    assert!(Packet::decode(&page.encode(&key(1))).is_none());
    let request = packet(Body::GetProviders {
        topic: contact(90).id,
        after: None,
    });
    let mut encoded = request.encode(&key(1));
    let payload_end = encoded.len() - 64;
    encoded[payload_end - 1] = 2;
    let signature = key(1).sign(&encoded[..payload_end]);
    encoded[payload_end..].copy_from_slice(&signature.to_bytes());
    assert!(Packet::decode(&encoded).is_none());
    let mut old = request.encode(&key(1));
    old[4] = 4;
    let signature = key(1).sign(&old[..payload_end]);
    old[payload_end..].copy_from_slice(&signature.to_bytes());
    assert!(Packet::decode(&old).is_none());
}

#[test]
fn provider_quota_preserves_renewal_and_other_providers_capacity() {
    let mut coordinator = core(2);
    let mut provider = core(1);
    for n in 0..16 {
        let actions = provider
            .register(contact(2), NodeId::from_bytes([n; 32]), at(100))
            .unwrap();
        pair(&mut provider, &mut coordinator, actions, at(100));
    }
    assert_eq!(coordinator.registration_len(), 16);
    let topic = NodeId::from_bytes([99; 32]);
    let actions = provider.register(contact(2), topic, at(101)).unwrap();
    pair(&mut provider, &mut coordinator, actions, at(101));
    assert_eq!(coordinator.registration_len(), 16);
    let actions = provider
        .register(contact(2), NodeId::from_bytes([0; 32]), at(101))
        .unwrap();
    pair(&mut provider, &mut coordinator, actions, at(101));
    assert_eq!(
        coordinator.registrations[&(NodeId::from_bytes([0; 32]), contact(1).id)]
            .record
            .expires,
        401
    );
    let other = Record::sign(&key(3), topic, contact(2), 401, [9; 32]);
    assert!(coordinator
        .handle_request(contact(3), &Body::Register(other), at(101), &mut vec![])
        .is_some());
    assert_eq!(coordinator.registration_len(), 17);
}

#[test]
fn replay_quota_keeps_cached_replies_and_room_for_other_peers() {
    let mut receiver = core(2);
    let p = challenged(&mut receiver, packet(Body::Probe));
    for i in 0..256u16 {
        let mut nonce = [0; 32];
        nonce[..2].copy_from_slice(&i.to_le_bytes());
        receiver.replay.insert(
            (contact(1).id, nonce),
            Replay {
                expires: 120_000,
                from: addr(1),
                response: vec![7],
                packet: None,
            },
        );
    }
    assert!(receiver
        .receive(addr(1), &p.encode(&key(1)), at(100))
        .is_empty());
    let mut cached = p;
    cached.nonce = [0; 32];
    assert_eq!(
        sent(&receiver.receive(addr(1), &cached.encode(&key(1)), at(100))),
        vec![7]
    );
    assert_eq!(receiver.replay.len(), 256);
    let mut other = packet(Body::Probe);
    other.key = key(3).public();
    let challenge = Packet::decode(&sent(&receiver.receive(
        addr(3),
        &other.encode(&key(3)),
        at(100),
    )))
    .unwrap();
    other.epoch = challenge.epoch;
    other.cookie = challenge.cookie;
    assert!(matches!(
        Packet::decode(&sent(&receiver.receive(
            addr(3),
            &other.encode(&key(3)),
            at(100)
        )))
        .unwrap()
        .body,
        Body::Ack
    ));
    assert_eq!(receiver.replay.len(), 257);
}

#[test]
fn protocol_v6_golden_vectors() {
    let topic = contact(90).id;
    let record = Record::sign(&key(3), topic, contact(1), 300, [9; 32]);
    let cases = [
        (
            "store-immutable",
            packet(Body::PutValue {
                value: Value::Immutable(b"immutable".to_vec()),
                cas: None,
            }),
        ),
        (
            "store-mutable",
            packet(Body::PutValue {
                value: Value::from(
                    MutableValue::sign(&key(3), b"test".to_vec(), 7, b"mutable".to_vec(), 300)
                        .unwrap(),
                ),
                cas: Some(6),
            }),
        ),
        (
            "value-result",
            packet(Body::ValueResult(Some(Value::Immutable(
                b"immutable".to_vec(),
            )))),
        ),
        ("find-value", packet(Body::FindValue(topic))),
        (
            "value-nodes-empty",
            packet(Body::ValueNodes {
                contacts: vec![contact(3)],
                value: None,
            }),
        ),
        (
            "value-nodes-mutable",
            packet(Body::ValueNodes {
                contacts: vec![contact(3)],
                value: Some(Value::from(
                    MutableValue::sign(&key(3), b"test".to_vec(), 7, b"mutable".to_vec(), 300)
                        .unwrap(),
                )),
            }),
        ),
        ("reflect", packet(Body::Reflect)),
        (
            "reflected",
            packet(Body::Reflected("[2001:db8::1]:9000".parse().unwrap())),
        ),
        ("probe", packet(Body::Probe)),
        (
            "providers-first",
            packet(Body::GetProviders { topic, after: None }),
        ),
        (
            "providers-next",
            packet(Body::GetProviders {
                topic,
                after: Some(contact(3).id),
            }),
        ),
        (
            "providers-page",
            packet(Body::ProviderPage {
                records: vec![record],
                next: Some(contact(3).id),
            }),
        ),
    ];
    for (name, packet) in cases {
        let encoded = packet.encode(&key(1));
        let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
        let expected = match name {
            "reflect" => include_str!("../tests/vectors/v6-reflect.hex"),
            "reflected" => include_str!("../tests/vectors/v6-reflected.hex"),
            "probe" => include_str!("../tests/vectors/v6-probe.hex"),
            "providers-first" => include_str!("../tests/vectors/v6-providers-first.hex"),
            "providers-next" => include_str!("../tests/vectors/v6-providers-next.hex"),
            "providers-page" => include_str!("../tests/vectors/v6-providers-page.hex"),
            "store-immutable" => include_str!("../tests/vectors/v6-store-immutable.hex"),
            "store-mutable" => include_str!("../tests/vectors/v6-store-mutable.hex"),
            "value-result" => include_str!("../tests/vectors/v6-value-result.hex"),
            "find-value" => include_str!("../tests/vectors/v6-find-value.hex"),
            "value-nodes-empty" => include_str!("../tests/vectors/v6-value-nodes-empty.hex"),
            "value-nodes-mutable" => include_str!("../tests/vectors/v6-value-nodes-mutable.hex"),
            _ => unreachable!(),
        };
        assert_eq!(hex, expected.trim(), "wire vector {name}");
        assert_eq!(Packet::decode(&encoded).unwrap().body, packet.body);
    }
}

#[test]
fn value_replies_are_bound_to_the_requested_key_and_signature() {
    let mut d = core(2);
    let value = Value::Immutable(b"expected".to_vec());
    let (nonce, _) = d.get_value(contact(1), value.key(), at(100)).unwrap();
    let mut response = packet(Body::ValueResult(Some(Value::Immutable(b"wrong".to_vec()))));
    response.nonce = nonce;
    assert!(d
        .receive(addr(1), &response.encode(&key(1)), at(100))
        .is_empty());
    assert_eq!(d.pending_len(), 1);
    response.body = Body::ValueResult(Some(value.clone()));
    let events = d.receive(addr(1), &response.encode(&key(1)), at(100));
    assert!(events.iter().any(|a| matches!(a, Action::Event(e) if matches!(&**e, Event::Value { request, value: Some(got), .. } if *request == nonce && got == &value))));
    let mutable =
        MutableValue::sign(&key(3), vec![1; MAX_SALT], 5, vec![2; MAX_VALUE], 400).unwrap();
    let (nonce, _) = d.get_value(contact(1), mutable.key(), at(100)).unwrap();
    let mut forged = mutable.clone();
    forged.sequence += 1;
    response.nonce = nonce;
    response.body = Body::ValueResult(Some(Value::from(forged)));
    assert!(d
        .receive(addr(1), &response.encode(&key(1)), at(100))
        .is_empty());
    assert_eq!(d.pending_len(), 1);
    response.body = Body::ValueResult(Some(Value::from(mutable.clone())));
    response.exchange = vec![0; 48];
    assert!(response.encode(&key(1)).len() <= protocol::MAX_PACKET);
    let put = packet(Body::PutValue {
        value: Value::from(mutable),
        cas: Some(4),
    });
    assert!(put.encode(&key(1)).len() + 48 <= protocol::MAX_PACKET);
    assert_eq!(Packet::decode(&put.encode(&key(1))).unwrap().body, put.body);
}

#[test]
fn registration_rotates_aged_keys_and_retirement_has_a_timer() {
    let mut d = core(1);
    d.register(contact(2), contact(3).id, at(100)).unwrap();
    let original = d.signaling_key.public.clone();
    d.register(contact(2), contact(3).id, at(399)).unwrap();
    assert_eq!(d.signaling_key.public, original);
    d.register(contact(2), contact(3).id, at(400)).unwrap();
    assert_ne!(d.signaling_key.public, original);
    assert_eq!(d.retired_signaling_keys.len(), 1);
    d.rotate_signaling_key(at(400)).unwrap();
    d.rotate_signaling_key(at(400)).unwrap();
    assert_eq!(d.rotate_signaling_key(at(400)), Err(Error::Capacity));
    d.tick(at(410));
    assert_eq!(d.poll_timeout(), Some(700_000));
    d.tick(at(700));
    assert!(d.retired_signaling_keys.is_empty());
    assert_eq!(d.poll_timeout(), None);
}

#[test]
fn noncanonical_value_lengths_are_rejected_in_signed_and_compact_packets() {
    let request = packet(Body::PutValue {
        value: Value::Immutable(vec![b'x']),
        cas: None,
    });
    let encoded = request.encode(&key(1));
    assert!(Packet::decode(&encoded).is_some());
    let mut malformed = encoded[..encoded.len() - 64].to_vec();
    let length = malformed.len() - 3;
    assert_eq!(malformed[length], 1);
    malformed[length] = 0x81;
    malformed.insert(length + 1, 0);
    malformed.extend_from_slice(&key(1).sign(&malformed).to_bytes());
    assert!(Packet::decode(&malformed).is_none());
    let mut compact = request.compact();
    assert!(Packet::from_compact(&compact, request.key, request.destination).is_some());
    let length = compact.len() - 3;
    compact[length] = 0x81;
    compact.insert(length + 1, 0);
    assert!(Packet::from_compact(&compact, request.key, request.destination).is_none());
}

proptest! {
    #[test]
    fn arbitrary_signed_bodies_are_bounded(payload in prop::collection::vec(any::<u8>(), 0..994)) {
        let original = packet(Body::Probe).encode(&key(1));
        let mut bytes = original[..143].to_vec();
        bytes.extend_from_slice(&payload);
        let signature = key(1).sign(&bytes);
        bytes.extend_from_slice(&signature.to_bytes());
        if let Some(decoded) = Packet::decode(&bytes) {
            prop_assert!(decoded.encode(&key(1)).len() <= protocol::MAX_PACKET);
        }
    }
    #[test]
    fn mutable_value_roundtrip_binds_every_sequence(salt in prop::collection::vec(any::<u8>(), 0..33), bytes in prop::collection::vec(any::<u8>(), 0..513), sequence in any::<u64>()) {
        let value = MutableValue::sign(&key(3), salt, sequence, bytes, 300).unwrap();
        let request = packet(Body::PutValue { value: Value::from(value.clone()), cas: None });
        prop_assert_eq!(Packet::decode(&request.encode(&key(1))).unwrap().body, request.body);
        prop_assert!(value.verify(at(100)));
        let reply = packet(Body::ValueNodes { contacts: vec![contact(1), contact(3)], value: Some(Value::from(value.clone())) });
        prop_assert_eq!(Packet::decode(&reply.encode(&key(1))).unwrap().body, reply.body);
        let mut altered = value; altered.sequence ^= 1;
        prop_assert!(!altered.verify(at(100)));
    }
}

fn value_lookup_reply(d: &Dht, peer: u8, value: Option<Value>, contacts: Vec<Contact>) -> Packet {
    let mut reply = packet(Body::ValueNodes { contacts, value });
    reply.key = key(peer).public();
    reply.nonce = d
        .pending
        .iter()
        .find(|(_, p)| p.contact == contact(peer) && matches!(p.packet.body, Body::FindValue(_)))
        .unwrap()
        .0
        .to_owned();
    reply
}

#[test]
fn lookup_cancellation_releases_only_application_owned_work() {
    let mut d = core(2);
    d.probe(contact(9), at(100)).unwrap();
    let value = Value::Immutable(b"canceled lookup".to_vec());
    let (value_query, _) = d
        .lookup_value(value.key(), &[contact(1), contact(3), contact(4)], at(100))
        .unwrap();
    let late = value_lookup_reply(&d, 3, Some(value.clone()), vec![]);
    let (other, _) = d.lookup(value.key(), &[contact(5)], at(100)).unwrap();
    let other_pending = d
        .pending
        .values()
        .filter(|p| p.query == Some(other))
        .count();
    assert!(other_pending > 0);
    assert!(d.cancel_lookup(value_query));
    assert!(!d.cancel_lookup(value_query));
    assert!(!d.queries.contains_key(&value_query));
    assert_eq!(d.pending_len(), other_pending + 1);
    assert!(d
        .receive(addr(3), &late.encode(&key(3)), at(101))
        .is_empty());
    assert_eq!(d.pending_len(), other_pending + 1);
    assert!(d.cancel_lookup(other));
    assert_eq!(d.pending_len(), 1);
    d.maintain_routing(at(102));
    let (routing, _) = d
        .lookup_for(value.key(), &[contact(6)], QueryOwner::Routing, at(102))
        .unwrap();
    d.publish(value.key(), &[contact(7)], at(102)).unwrap();
    let publication = *d
        .queries
        .iter()
        .find(|(_, query)| query.owner == QueryOwner::Publication(value.key()))
        .unwrap()
        .0;
    for internal in [routing, publication] {
        let count = d.pending_len();
        assert!(!d.cancel_lookup(internal));
        assert!(d.queries.contains_key(&internal));
        assert_eq!(d.pending_len(), count);
    }
}

#[test]
fn immutable_lookup_completes_on_first_verified_value_and_cancels_only_its_work() {
    let mut d = core(2);
    d.probe(contact(9), at(100)).unwrap();
    let value = Value::Immutable(b"found during traversal".to_vec());
    let (query, _) = d
        .lookup_value(value.key(), &[contact(1), contact(3), contact(4)], at(100))
        .unwrap();
    assert!(d
        .pending
        .values()
        .filter(|p| p.query == Some(query))
        .all(|p| matches!(p.packet.body, Body::FindValue(_))));
    let late = value_lookup_reply(&d, 3, Some(value.clone()), vec![]);
    let valid = value_lookup_reply(&d, 1, Some(value.clone()), vec![]);
    let mut forged = valid.clone();
    forged.body = Body::ValueNodes {
        contacts: vec![contact(8)],
        value: Some(Value::Immutable(b"wrong key".to_vec())),
    };
    assert!(d
        .receive(addr(1), &forged.encode(&key(1)), at(100))
        .is_empty());
    assert_eq!(d.pending_len(), 4);
    assert!(!d.queries[&query].contacts.contains_key(&contact(8).id));
    let actions = d.receive(addr(1), &valid.encode(&key(1)), at(100));
    let results: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Event(e) => match e.as_ref() {
                Event::ValueLookupDone {
                    query: id, result, ..
                } if *id == query => Some(result),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, Some(value));
    assert_eq!(results[0].responses, 1);
    assert_eq!(results[0].attempted, 3);
    assert!(!d.queries.contains_key(&query));
    assert_eq!(d.pending_len(), 1);
    assert!(d.pending.values().all(|p| p.contact == contact(9)));
    assert!(d
        .receive(addr(3), &late.encode(&key(3)), at(100))
        .is_empty());
}

#[test]
fn mutable_lookup_rejects_bad_signatures_and_compares_the_entire_frontier() {
    for (last_sequence, expected_conflict) in [(2, true), (3, false)] {
        let mut d = core(2);
        let signed = |seq, bytes: &[u8]| {
            Value::from(MutableValue::sign(&key(8), vec![], seq, bytes.to_vec(), 300).unwrap())
        };
        let first = signed(2, b"first");
        let (query, _) = d
            .lookup_value(first.key(), &[contact(1), contact(3), contact(4)], at(100))
            .unwrap();
        let reply = value_lookup_reply(&d, 1, Some(first), vec![]);
        let mut forged = reply.clone();
        if let Body::ValueNodes {
            value: Some(Value::Mutable(v)),
            ..
        } = &mut forged.body
        {
            v.sequence ^= 1;
        }
        assert!(d
            .receive(addr(1), &forged.encode(&key(1)), at(100))
            .is_empty());
        assert_eq!(d.pending_len(), 3);
        assert!(d
            .receive(addr(1), &reply.encode(&key(1)), at(100))
            .is_empty());
        let fork = value_lookup_reply(&d, 3, Some(signed(2, b"fork")), vec![]);
        assert!(d
            .receive(addr(3), &fork.encode(&key(3)), at(100))
            .is_empty());
        assert!(d.queries.contains_key(&query));
        let last = signed(last_sequence, b"last");
        let reply = value_lookup_reply(&d, 4, Some(last.clone()), vec![]);
        let actions = d.receive(addr(4), &reply.encode(&key(4)), at(100));
        let result = actions
            .iter()
            .find_map(|a| match a {
                Action::Event(e) => match e.as_ref() {
                    Event::ValueLookupDone { result, .. } => Some(result),
                    _ => None,
                },
                _ => None,
            })
            .unwrap();
        assert_eq!(result.responses, 3);
        assert_eq!(result.conflicting, expected_conflict);
        if !expected_conflict {
            assert_eq!(result.value, Some(last));
        }
    }
}

#[test]
fn value_lookup_reports_absence_failures_and_expiry_without_leaking_queries() {
    let mut d = core(2);
    let (_, actions) = d.lookup_value(contact(8).id, &[], at(100)).unwrap();
    assert!(
        matches!(&actions[0], Action::Event(e) if matches!(e.as_ref(), Event::ValueLookupDone { result, .. } if result.attempted == 0 && result.responses == 0))
    );
    let (query, _) = d
        .lookup_value(contact(8).id, &[contact(1)], at(100))
        .unwrap();
    let reply = value_lookup_reply(&d, 1, None, vec![]);
    let actions = d.receive(addr(1), &reply.encode(&key(1)), at(100));
    assert!(actions.iter().any(|a| matches!(a, Action::Event(e) if matches!(e.as_ref(), Event::ValueLookupDone { query: id, result, .. } if *id == query && result.value.is_none() && result.responses == 1))));
    let value = Value::from(MutableValue::sign(&key(8), vec![], 1, vec![1], 101).unwrap());
    let (query, _) = d
        .lookup_value(value.key(), &[contact(1), contact(3)], at(100))
        .unwrap();
    let reply = value_lookup_reply(&d, 1, Some(value), vec![]);
    d.receive(addr(1), &reply.encode(&key(1)), at(100));
    let actions = d.tick(at(140));
    assert!(actions.iter().any(|a| matches!(a, Action::Event(e) if matches!(e.as_ref(), Event::ValueLookupDone { query: id, result, .. } if *id == query && result.value.is_none() && result.responses == 1 && result.attempted == 2 && result.timed_out))));
    assert!(d.queries.is_empty());
    assert_eq!(d.pending_len(), 0);
}

#[test]
fn value_referrals_are_packet_bounded_and_old_wire_versions_are_rejected() {
    let contacts: Vec<_> = (1..=protocol::MAX_CONTACTS)
        .map(|n| {
            Contact::new(
                contact(n as u8).id,
                format!("[2001:db8::{n}]:65535").parse().unwrap(),
            )
        })
        .collect();
    let mutable = Value::from(
        MutableValue::sign(
            &key(3),
            vec![7; MAX_SALT],
            u64::MAX,
            vec![42; MAX_VALUE],
            300,
        )
        .unwrap(),
    );
    for value in [
        None,
        Some(Value::Immutable(vec![42; MAX_VALUE])),
        Some(mutable),
    ] {
        let limit = if value.is_some() {
            protocol::MAX_VALUE_CONTACTS
        } else {
            protocol::MAX_CONTACTS
        };
        let mut p = packet(Body::ValueNodes {
            contacts: contacts[..limit].to_vec(),
            value,
        });
        p.exchange = vec![1; 48];
        let bytes = p.encode(&key(1));
        assert!(bytes.len() <= protocol::MAX_PACKET);
        assert_eq!(Packet::decode(&bytes).unwrap().body, p.body);
        if let Body::ValueNodes { contacts: refs, .. } = &mut p.body {
            refs.push(contacts[limit % contacts.len()]);
        }
        assert!(Packet::decode(&p.encode(&key(1))).is_none());
    }
    let mut old = packet(Body::Probe).encode(&key(1));
    old[4] = 5;
    let end = old.len() - 64;
    let signature = key(1).sign(&old[..end]);
    old[end..].copy_from_slice(&signature.to_bytes());
    assert!(Packet::decode(&old).is_none());
}

#[test]
fn reflection_requires_cookie_and_reports_the_request_socket() {
    let mut receiver = core(2);
    let mut request = packet(Body::Reflect);
    request.server = false;
    let valid = challenged(&mut receiver, request);
    let actions = receiver.receive(addr(1), &valid.encode(&key(1)), at(100));
    let reply = actions
        .iter()
        .find_map(|a| match a {
            Action::Send { bytes, .. } => Packet::decode(bytes),
            _ => None,
        })
        .unwrap();
    assert_eq!(reply.body, Body::Reflected(addr(1)));
    assert_eq!(receiver.routing_len(), 0);
    assert!(reply.encode(&key(2)).len() <= protocol::MAX_PACKET);
    for body in [
        Body::Reflect,
        Body::Reflected("[2001:db8::1]:9000".parse().unwrap()),
    ] {
        let packet = packet(body.clone());
        assert_eq!(Packet::decode(&packet.encode(&key(1))).unwrap().body, body);
        assert_eq!(
            Packet::from_compact(&packet.compact(), packet.key, packet.destination)
                .unwrap()
                .body,
            body
        );
    }
}

#[test]
fn reflection_matches_nonce_endpoint_kind_and_usable_address_before_completion() {
    let mut receiver = core(2);
    let (request, _) = receiver.reflect(contact(1), at(100)).unwrap();
    let mut reply = packet(Body::Reflected(addr(2)));
    reply.nonce = request;
    assert!(receiver
        .receive(addr(3), &reply.encode(&key(1)), at(100))
        .is_empty());
    reply.nonce = [0; 32];
    assert!(receiver
        .receive(addr(1), &reply.encode(&key(1)), at(100))
        .is_empty());
    reply.nonce = request;
    for body in [Body::Ack, Body::Reflected("0.0.0.0:80".parse().unwrap())] {
        reply.body = body;
        assert!(receiver
            .receive(addr(1), &reply.encode(&key(1)), at(100))
            .is_empty());
        assert_eq!(receiver.pending_len(), 1);
    }
    reply.body = Body::Reflected(addr(2));
    let actions = receiver.receive(addr(1), &reply.encode(&key(1)), at(100));
    assert!(actions.iter().any(|a| matches!(a, Action::Event(event)
        if matches!(**event, Event::ObservedAddress { request: id, reflector, address }
            if id == request && reflector == contact(1) && address == addr(2)))));
    assert_eq!(receiver.pending_len(), 0);
}

#[test]
fn bootstrap_hints_are_bounded_live_and_revalidated() {
    let mut dht = core(2);
    // Populate verified-route storage directly to exercise a full export without
    // spending this test on hundreds of already-tested cookie handshakes.
    for bucket in 0..8 {
        for n in 0..20 {
            let mut id = *dht.id().as_bytes();
            id[0] ^= 0x80 >> bucket;
            id[31] ^= n;
            let c = Contact::new(NodeId::from_bytes(id), addr(bucket * 20 + n));
            dht.routes.insert(
                c.id,
                Route {
                    contact: c,
                    expires: 200_000,
                },
            );
        }
    }
    let hints = dht.bootstrap_contacts(at(100));
    assert_eq!(hints.len(), MAX_CANDIDATES);
    assert_eq!(
        hints.iter().map(|c| c.id).collect::<BTreeSet<_>>().len(),
        MAX_CANDIDATES
    );
    assert!(dht.bootstrap_contacts(at(200)).is_empty());
    let mut fresh = core(2);
    let (_, actions) = fresh.bootstrap(&hints, at(100)).unwrap();
    assert!(actions.iter().any(|a| matches!(a, Action::Send { .. })));
    assert_eq!(
        fresh.routing_len(),
        0,
        "hints must not become trusted routes"
    );
}

#[test]
fn network_change_invalidates_cookies_and_queries_but_keeps_content_and_signaling_key() {
    let mut dht = core(2);
    let valid = challenged(&mut dht, packet(Body::Probe));
    dht.receive(addr(1), &valid.encode(&key(1)), at(100));
    let content = Value::Immutable(b"retained".to_vec());
    assert!(dht.store_value(contact(1), &content, None, at(100)));
    let signaling_public = dht.signaling_key.public.clone();
    let topic = node_id(key(3).public());
    dht.publish(topic, &[contact(1)], at(100)).unwrap();
    let (old_query, _) = dht.lookup(topic, &[contact(1)], at(100)).unwrap();
    let old_nonce = dht.nonce();
    assert_eq!(
        dht.network_changed([9; 32], &[contact(2)], at(101)),
        Err(Error::Invalid)
    );
    assert!(dht.queries.contains_key(&old_query));
    let actions = dht
        .network_changed([10; 32], &[contact(3)], at(101))
        .unwrap();
    assert_eq!(
        actions.first(),
        Some(&Action::event(Event::NetworkChanged(1)))
    );
    assert!(!dht.queries.contains_key(&old_query));
    assert_eq!(dht.routing_len(), 0);
    assert_eq!(dht.signaling_key.public, signaling_public);
    assert!(dht.values.contains_key(&content.key()));
    assert!(dht.publications.contains_key(&topic));
    assert_ne!(dht.nonce(), old_nonce);
    let replies = dht.receive(addr(1), &valid.encode(&key(1)), at(101));
    assert!(replies
        .iter()
        .any(|action| matches!(action, Action::Send { bytes, .. }
        if Packet::decode(bytes).is_some_and(|packet| matches!(packet.body, Body::Challenge)))));
}

mod network;

#[test]
fn referrals_cannot_evict_an_unqueried_independent_seed() {
    let mut d = core(2);
    let local = d.id();
    let honest = lookup_candidate(500, "203.0.113.1:4000");
    let (id, _) = d
        .lookup(
            NodeId::from_bytes([0; 32]),
            &[contact(100), honest],
            at(100),
        )
        .unwrap();
    let q = d.queries.get_mut(&id).unwrap();
    q.contacts.get_mut(&contact(100).id).unwrap().status = Status::Done;
    q.contacts.get_mut(&honest.id).unwrap().status = Status::Fresh;
    // A signed referrer can advertise a different identity at the seed's IP.
    // The closer referral must not displace an independently supplied endpoint.
    let closer = lookup_candidate(1, "203.0.113.1:5000");
    q.add_candidates(
        local,
        RoutingPolicy::Diverse,
        Some(contact(100).id),
        [closer],
    );
    assert!(q.contacts.contains_key(&honest.id));
    assert!(!q.contacts.contains_key(&closer.id));
    assert_eq!(q.origin(honest.id), honest.id);
}

#[test]
fn default_lookup_queries_independent_seeds_outside_the_nearest_twenty() {
    for policy in [RoutingPolicy::Diverse, RoutingPolicy::Unrestricted] {
        let mut d = Dht::with_routing_policy(key(2), [102; 32], true, policy);
        let honest = lookup_candidate(1000, "203.0.113.1:4000");
        let (id, _) = d
            .lookup(NodeId::from_bytes([0; 32]), &[honest], at(100))
            .unwrap();
        d.pending.clear();
        let q = d.queries.get_mut(&id).unwrap();
        q.contacts.get_mut(&honest.id).unwrap().status = Status::Fresh;
        // Model twenty authenticated, target-near collaborators already answered.
        // Their presence must not let completion skip an untouched honest root.
        for n in 1..=20 {
            let contact = lookup_candidate(n, &format!("198.51.{n}.1:4000"));
            q.contacts.insert(
                contact.id,
                Candidate {
                    contact,
                    status: Status::Done,
                    referrer: None,
                },
            );
        }
        let mut actions = Vec::new();
        d.drive_queries(at(100), &mut actions);
        let queried = actions
            .iter()
            .any(|a| matches!(a, Action::Send { to, .. } if *to == honest.addr));
        assert_eq!(queried, policy == RoutingPolicy::Diverse);
        if policy == RoutingPolicy::Diverse {
            assert!(d.queries[&id].contacts[&honest.id].status == Status::Flight);
            assert!(!actions.iter().any(
                |a| matches!(a, Action::Event(e) if matches!(&**e, Event::LookupDone { .. }))
            ));
        }
    }
}

#[test]
fn cached_routes_do_not_expand_the_completion_frontier() {
    let mut d = core(2);
    let far = lookup_candidate(1000, "203.0.113.1:4000");
    for contact in (1..=20)
        .map(|n| lookup_candidate(n, &format!("198.51.{n}.1:4000")))
        .chain([far])
    {
        d.routes.insert(
            contact.id,
            Route {
                contact,
                expires: at(200).monotonic_ms,
            },
        );
    }
    let (id, _) = d.lookup(NodeId::from_bytes([0; 32]), &[], at(100)).unwrap();
    d.pending.clear();
    let q = d.queries.get_mut(&id).unwrap();
    assert!(q.protected_seeds.is_empty());
    for (id, c) in &mut q.contacts {
        c.status = if *id == far.id {
            Status::Fresh
        } else {
            Status::Done
        };
    }
    let mut actions = Vec::new();
    d.drive_queries(at(100), &mut actions);
    assert!(!actions.iter().any(|a| matches!(a, Action::Send { .. })));
    assert!(actions.iter().any(|a| matches!(a, Action::Event(e) if matches!(&**e, Event::LookupDone { query, .. } if *query == id))));
}
