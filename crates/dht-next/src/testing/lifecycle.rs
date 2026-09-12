use crate::*;
use std::collections::VecDeque;

const NODES: usize = 4;
const QUEUE_LIMIT: usize = 512;

struct Datagram {
    from: SocketAddr,
    to: SocketAddr,
    bytes: Vec<u8>,
}

struct Network {
    nodes: Vec<Dht>,
    contacts: Vec<Contact>,
    online: [bool; NODES],
    isolated: [bool; NODES],
    discard: [bool; NODES],
    queue: VecDeque<Datagram>,
    events: VecDeque<(usize, Event)>,
    now: u64,
    generation: u64,
    emitted: usize,
}

impl Network {
    fn new() -> Self {
        let nodes: Vec<_> = (0..NODES).map(|i| Self::node(i, 0)).collect();
        let contacts = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| Contact::new(n.id(), SocketAddr::from(([192, 0, i as u8, 1], 4000))))
            .collect();
        Self {
            nodes,
            contacts,
            online: [true; NODES],
            isolated: [false; NODES],
            discard: [false; NODES],
            queue: VecDeque::new(),
            events: VecDeque::new(),
            now: 100_000,
            generation: 0,
            emitted: 0,
        }
    }

    fn node(i: usize, generation: u64) -> Dht {
        let mut secret = [100 + i as u8; 32];
        secret[..8].copy_from_slice(&generation.to_le_bytes());
        Dht::new(Keypair::from_seed(&[i as u8 + 1; 32]), secret, i >= 2)
    }

    fn time(&self) -> Time {
        Time::new(self.now, self.now / 1000)
    }

    fn actions(&mut self, source: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send { to, bytes } => {
                    assert!(bytes.len() <= protocol::MAX_PACKET);
                    self.emitted += 1;
                    assert!(self.emitted <= 100_000, "scenario traffic budget exceeded");
                    if self.queue.len() < QUEUE_LIMIT {
                        self.queue.push_back(Datagram {
                            from: self.contacts[source].addr,
                            to,
                            bytes,
                        });
                    }
                }
                Action::Event(event) => {
                    let session = match &*event {
                        Event::Incoming { signal, .. } => Some(signal.envelope.session),
                        _ => None,
                    };
                    if self.events.len() == 256 {
                        self.events.pop_front();
                    }
                    self.events.push_back((source, *event));
                    if let Some(session) = session {
                        let now = self.time();
                        if let Ok(reply) =
                            self.nodes[source].answer(session, b"answer".to_vec(), now)
                        {
                            self.actions(source, reply);
                        }
                    }
                }
            }
        }
        self.bounds();
    }

    fn bounds(&self) {
        for n in &self.nodes {
            assert!(n.pending.len() <= MAX_PENDING);
            assert!(n.queries.len() <= MAX_QUERIES);
            assert!(n
                .queries
                .values()
                .all(|q| q.contacts.len() <= MAX_CANDIDATES));
            assert!(n.routes.len() <= MAX_ROUTING);
            assert!(n.peers.len() <= MAX_PEERS);
            assert!(n.replay.len() <= MAX_REPLAYS);
            assert!(n.registrations.len() <= MAX_REGISTRATIONS);
            assert!(n.authorizations.len() <= MAX_REGISTRATIONS);
            assert!(n.managed.len() <= MAX_REGISTRATIONS);
            assert!(n.incoming.len() <= MAX_SESSIONS);
            assert!(n.outgoing.len() <= MAX_SESSIONS);
            assert!(n.exchanges.len() <= MAX_SESSIONS);
            assert!(n.publications.len() <= MAX_PUBLICATIONS);
            assert!(n.values.len() <= MAX_VALUES);
        }
    }

    fn deliver(&mut self, index: usize, duplicate: bool, corrupt: bool) {
        if self.queue.is_empty() {
            return;
        }
        let mut packet = self.queue.remove(index % self.queue.len()).unwrap();
        if duplicate && self.queue.len() < QUEUE_LIMIT {
            self.queue.push_back(Datagram {
                from: packet.from,
                to: packet.to,
                bytes: packet.bytes.clone(),
            });
        }
        if corrupt && !packet.bytes.is_empty() {
            packet.bytes[0] ^= 0xff;
        }
        let Some(dest) = self.contacts.iter().position(|c| c.addr == packet.to) else {
            return;
        };
        let source = self.contacts.iter().position(|c| c.addr == packet.from);
        if !self.online[dest] || self.isolated[dest] || source.is_some_and(|s| self.isolated[s]) {
            return;
        }
        let now = self.time();
        let actions = self.nodes[dest].receive(packet.from, &packet.bytes, now);
        if self.discard[dest] {
            self.nodes[dest].values.clear();
        }
        self.actions(dest, actions);
    }

    fn pump(&mut self) {
        for _ in 0..4096 {
            if self.queue.is_empty() {
                return;
            }
            self.deliver(0, false, false);
        }
        panic!("delivery failed to quiesce");
    }

    fn advance(&mut self, millis: u64) {
        self.now += millis;
        let now = self.time();
        for i in 0..NODES {
            if self.online[i] {
                let actions = self.nodes[i].tick(now);
                self.actions(i, actions);
            }
        }
    }

    fn step(&mut self, bytes: &[u8]) {
        let [op, source, arg, scheduling] = <[u8; 4]>::try_from(bytes).unwrap();
        let source = source as usize % NODES;
        let dest = (source + 1 + arg as usize % (NODES - 1)) % NODES;
        let contact = self.contacts[dest];
        let topic = self.contacts[source].id;
        let now = self.time();
        let value = Value::Immutable(vec![arg; 16]);
        let mut actions = Vec::new();
        if self.online[source] {
            match op % 16 {
                0 => {
                    actions = self.nodes[source]
                        .bootstrap(&[contact], now)
                        .map(|(_, a)| a)
                        .unwrap_or_default()
                }
                1 => {
                    if let Ok((q, a)) = self.nodes[source].lookup(topic, &[contact], now) {
                        actions = a;
                        if arg & 1 != 0 {
                            self.nodes[source].cancel_lookup(q);
                        }
                    }
                }
                2 => {
                    actions = self.nodes[source]
                        .publish(topic, &[contact], now)
                        .unwrap_or_default()
                }
                3 => {
                    self.nodes[source].unpublish(topic);
                }
                4 => {
                    if let Ok((request, a)) =
                        self.nodes[source].put_value(contact, value, None, now)
                    {
                        actions = a;
                        if arg & 1 != 0 {
                            self.nodes[source].cancel_value_write(request);
                        }
                    }
                }
                5 => {
                    if let Ok((request, a)) =
                        self.nodes[source].get_value(contact, value.key(), now)
                    {
                        actions = a;
                        if arg & 1 != 0 {
                            self.nodes[source].cancel_value_read(request);
                        }
                    }
                }
                6 => {
                    if let Ok((q, a)) =
                        self.nodes[source].lookup_value(value.key(), &[contact], now)
                    {
                        actions = a;
                        if arg & 1 != 0 {
                            self.nodes[source].cancel_lookup(q);
                        }
                    }
                }
                7 => {
                    self.generation += 1;
                    self.contacts[source]
                        .addr
                        .set_port(4000 + self.generation as u16);
                    actions = self.nodes[source]
                        .network_changed(
                            crypto::hash(&self.generation.to_le_bytes()),
                            &[contact],
                            now,
                        )
                        .unwrap();
                }
                8 => self.online[source] = false,
                9 => self.isolated[source] = !self.isolated[source],
                10 => self.discard[source] = !self.discard[source],
                11 => {
                    actions = self.nodes[source]
                        .register(contact, topic, now)
                        .unwrap_or_default()
                }
                12 => {
                    let records: Vec<_> = self
                        .events
                        .iter()
                        .filter_map(|(_, e)| match e {
                            Event::Registered(r) => Some(r.clone()),
                            _ => None,
                        })
                        .take(MAX_COORDINATORS)
                        .collect();
                    actions = self.nodes[source]
                        .signal_via(&records, b"offer".to_vec(), now)
                        .map(|(_, a)| a)
                        .unwrap_or_default();
                }
                _ => {}
            }
        } else if op % 16 == 8 {
            self.generation += 1;
            self.nodes[source] = Self::node(source, self.generation);
            self.online[source] = true;
        }
        self.actions(source, actions);
        self.advance(u64::from(scheduling) * 20);
        match op % 16 {
            13 => {
                self.queue.pop_front();
            }
            14 => self.deliver(arg as usize, true, false),
            15 => self.deliver(arg as usize, false, true),
            _ => {
                for _ in 0..scheduling % 8 {
                    self.deliver(arg as usize, false, false);
                }
            }
        }
        self.bounds();
    }

    fn expect_event(&mut self, source: usize, matches: impl Fn(&Event) -> bool) {
        for _ in 0..=60 {
            self.pump();
            if self.events.iter().any(|(i, e)| *i == source && matches(e)) {
                return;
            }
            self.advance(1000);
        }
        panic!("recovery deadline exceeded: {:?}", self.events);
    }

    fn recover(&mut self) {
        self.isolated.fill(false);
        self.discard.fill(false);
        for i in 0..NODES {
            if !self.online[i] {
                self.generation += 1;
                self.nodes[i] = Self::node(i, self.generation);
                self.online[i] = true;
            }
            let topics: Vec<_> = self.nodes[i].publications.keys().copied().collect();
            for topic in topics {
                self.nodes[i].unpublish(topic);
            }
            let managed: Vec<_> = self.nodes[i].managed.keys().copied().collect();
            for (topic, coordinator) in managed {
                self.nodes[i].stop_renewing(topic, coordinator);
            }
        }
        for _ in 0..70 {
            self.advance(1000);
            self.pump();
        }
        for n in &self.nodes {
            assert!(n.pending.values().all(|p| p.query.is_some_and(|q| n
                .queries
                .get(&q)
                .is_some_and(|q| q.owner == QueryOwner::Routing))));
            assert!(n.queries.values().all(|q| q.owner == QueryOwner::Routing));
            assert!(n.outgoing.is_empty());
        }
        self.events.clear();
        let now = self.time();
        let value = Value::Immutable(b"recovery sentinel".to_vec());
        let (request, actions) = self.nodes[0]
            .put_value(self.contacts[2], value.clone(), None, now)
            .unwrap();
        self.actions(0, actions);
        self.expect_event(
            0,
            |e| matches!(e, Event::ValueStored { request: r, stored: true, .. } if *r == request),
        );
        let now = self.time();
        let (query, actions) = self.nodes[1]
            .lookup_value(value.key(), &[self.contacts[2]], now)
            .unwrap();
        self.actions(1, actions);
        self.expect_event(1, |e| matches!(e, Event::ValueLookupDone { query: q, result, .. } if *q == query && result.value.as_ref() == Some(&value)));
        self.events.clear();
        let now = self.time();
        let actions = self.nodes[1]
            .register(self.contacts[2], self.contacts[1].id, now)
            .unwrap();
        self.actions(1, actions);
        self.expect_event(1, |e| matches!(e, Event::Registered(_)));
        let record = self
            .events
            .iter()
            .rev()
            .find_map(|(i, e)| match e {
                Event::Registered(r) if *i == 1 => Some(r.clone()),
                _ => None,
            })
            .unwrap();
        let now = self.time();
        let (session, actions) = self.nodes[0]
            .signal(record, b"offer".to_vec(), now)
            .unwrap();
        self.actions(0, actions);
        self.expect_event(0, |e| matches!(e, Event::Answered(s) if s.envelope.session == session && s.payload == b"answer"));
        self.bounds();
    }
}

/// Fuzz up to 32 four-byte lifecycle operations, then require honest recovery.
pub fn fuzz_lifecycle(input: &[u8]) {
    let mut network = Network::new();
    for operation in input.chunks_exact(4).take(32) {
        network.step(operation);
    }
    network.recover();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_operation_matrix_recovers() {
        fuzz_lifecycle(&[]);
        for offset in 0..16u8 {
            let input: Vec<_> = (0..32u8)
                .flat_map(|i| [i.wrapping_add(offset), i % 4, i.wrapping_mul(17), 7])
                .collect();
            fuzz_lifecycle(&input);
        }
    }
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(32))]
        #[test]
        fn arbitrary_lifecycles_recover(input in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=128)) {
            fuzz_lifecycle(&input);
        }
    }
}
