//! Bounded topic publication through discovered, authenticated coordinators.
use super::*;

pub const MAX_PUBLICATIONS: usize = 16;
const MAX_SEEDS: usize = 8;

pub(super) struct Publication {
    seeds: Vec<Contact>,
    owned: BTreeMap<NodeId, Contact>,
    query: Option<u64>,
    pub(super) next_at: u64,
    failures: u8,
    cooldown: BTreeMap<NodeId, u64>,
}

impl Dht {
    pub(super) fn restart_publications(&mut self, seeds: &[Contact], now: Time) -> Vec<Action> {
        for publication in self.publications.values_mut() {
            let mut hints = Vec::new();
            for contact in seeds
                .iter()
                .chain(publication.owned.values())
                .chain(publication.seeds.iter())
            {
                if hints.len() < MAX_SEEDS && !hints.contains(contact) {
                    hints.push(*contact);
                }
            }
            publication.seeds = hints;
            publication.owned.clear();
            publication.query = None;
            publication.failures = 0;
            publication.cooldown.clear();
            publication.next_at = now.monotonic_ms;
        }
        let mut actions = Vec::new();
        self.discover_publications(now, &mut actions);
        actions
    }
    /// Discover up to three coordinators near `topic` and maintain their leases.
    /// Seeds are bootstrap hints, never trusted routing entries. Repeating a call
    /// updates changed seeds without duplicating an in-flight lookup.
    pub fn publish(
        &mut self,
        topic: NodeId,
        seeds: &[Contact],
        now: Time,
    ) -> Result<Vec<Action>, Error> {
        if seeds.len() > MAX_SEEDS || seeds.iter().any(|c| c.id == self.id() || !usable(c.addr)) {
            return Err(Error::Invalid);
        }
        if let Some(p) = self.publications.get_mut(&topic) {
            if p.seeds != seeds {
                p.seeds = seeds.to_vec();
                p.next_at = now.monotonic_ms;
            }
        } else {
            if self.publications.len() >= MAX_PUBLICATIONS {
                return Err(Error::Capacity);
            }
            self.publications.insert(
                topic,
                Publication {
                    seeds: seeds.to_vec(),
                    owned: BTreeMap::new(),
                    query: None,
                    next_at: now.monotonic_ms,
                    failures: 0,
                    cooldown: BTreeMap::new(),
                },
            );
        }
        let mut out = Vec::new();
        self.discover_publications(now, &mut out);
        Ok(out)
    }

    /// Stop this topic's discovery and only the renewals created by publication.
    /// Remote leases and existing local authorizations expire naturally.
    pub fn unpublish(&mut self, topic: NodeId) -> bool {
        let Some(p) = self.publications.remove(&topic) else {
            return false;
        };
        if let Some(query) = p.query {
            self.queries.remove(&query);
            self.pending.retain(|_, rpc| rpc.query != Some(query));
        }
        for coordinator in p.owned.keys() {
            if self
                .managed
                .get(&(topic, *coordinator))
                .is_some_and(|m| m.publication == Some(topic))
            {
                self.stop_renewing(topic, *coordinator);
            }
        }
        true
    }

    pub(super) fn discover_publications(&mut self, now: Time, out: &mut Vec<Action>) {
        let due: Vec<_> = self
            .publications
            .iter()
            .filter(|(_, p)| p.query.is_none() && p.next_at <= now.monotonic_ms)
            .map(|(topic, _)| *topic)
            .collect();
        for topic in due {
            let p = &self.publications[&topic];
            let seeds: Vec<_> = p
                .owned
                .values()
                .copied()
                .chain(p.seeds.iter().copied())
                .collect();
            match self.lookup_for(topic, &seeds, QueryOwner::Publication(topic), now) {
                Ok((_, actions)) => out.extend(actions),
                Err(_) => {
                    self.publications.get_mut(&topic).unwrap().next_at =
                        now.monotonic_ms.saturating_add(5000)
                }
            }
        }
    }

    pub(super) fn publication_query_started(&mut self, topic: NodeId, query: u64) {
        self.publications
            .get_mut(&topic)
            .expect("publication exists")
            .query = Some(query);
    }

    pub(super) fn publication_result(
        &mut self,
        topic: NodeId,
        closest: &[Contact],
        now: Time,
        out: &mut Vec<Action>,
    ) {
        let Some(p) = self.publications.get_mut(&topic) else {
            return;
        };
        p.cooldown.retain(|_, until| *until > now.monotonic_ms);
        let expected = p
            .seeds
            .iter()
            .chain(p.owned.values())
            .chain(closest)
            .map(|contact| contact.addr.ip().to_canonical())
            .collect::<BTreeSet<_>>()
            .len()
            .clamp(1, MAX_COORDINATORS);
        let mut ips = BTreeSet::new();
        let mut candidates: Vec<_> = closest
            .iter()
            .copied()
            .filter(|c| {
                self.routes
                    .get(&c.id)
                    .is_some_and(|r| r.contact == *c && r.expires > now.monotonic_ms)
            })
            .filter(|c| !p.cooldown.contains_key(&c.id))
            .filter(|c| {
                self.managed
                    .get(&(topic, c.id))
                    .is_none_or(|m| m.failures < 2)
            })
            .filter(|c| {
                self.managed
                    .get(&(topic, c.id))
                    .is_none_or(|m| m.publication == Some(topic))
            })
            .filter(|c| ips.insert(c.addr.ip().to_canonical()))
            .collect();
        let mut ordered = Vec::new();
        while ordered.len() < MAX_COORDINATORS {
            let Some(contact) = select_diverse_contact(&candidates, &ordered) else {
                break;
            };
            candidates.retain(|c| *c != contact);
            ordered.push(contact);
        }
        let selected: BTreeMap<_, _> = ordered.into_iter().map(|c| (c.id, c)).collect();
        // Failed/absent candidates lose renewal, not their already acknowledged lease.
        let retired: Vec<_> = p
            .owned
            .iter()
            .filter(|(id, c)| selected.get(id) != Some(c))
            .map(|(id, _)| *id)
            .collect();
        for id in retired {
            if self
                .managed
                .get(&(topic, id))
                .is_some_and(|m| m.publication == Some(topic))
            {
                self.stop_renewing(topic, id);
            }
            let p = self.publications.get_mut(&topic).unwrap();
            p.owned.remove(&id);
            if p.cooldown.len() < MAX_CANDIDATES {
                p.cooldown
                    .insert(id, now.monotonic_ms.saturating_add(120_000));
            }
        }
        for (id, contact) in selected {
            match self.maintain_registration_for(contact, topic, Some(topic), now) {
                Ok(actions) => {
                    out.extend(actions);
                    self.publications
                        .get_mut(&topic)
                        .unwrap()
                        .owned
                        .insert(id, contact);
                }
                Err(_) => break,
            }
        }
        let p = self.publications.get_mut(&topic).unwrap();
        p.query = None;
        let delay = if p.owned.len() < expected {
            p.failures = p.failures.saturating_add(1);
            (1000u64 << p.failures.min(6)).min(60_000)
        } else {
            p.failures = 0;
            let jitter = u64::from_le_bytes(
                blake3::keyed_hash(&self.secret, topic.as_bytes()).as_bytes()[..8]
                    .try_into()
                    .unwrap(),
            ) % 5000;
            30_000 + jitter
        };
        p.next_at = now.monotonic_ms.saturating_add(delay);
    }

    pub(super) fn publication_timeout(&self) -> Option<u64> {
        self.publications
            .values()
            .filter(|p| p.query.is_none())
            .map(|p| p.next_at)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_selection_prefers_distinct_prefixes_and_normalizes_aliases() {
        let mut d = Dht::with_routing_policy(
            Keypair::from_seed(&[1; 32]),
            [11; 32],
            false,
            RoutingPolicy::Unrestricted,
        );
        let now = Time::new(100_000, 100);
        let topic = NodeId::from_bytes([77; 32]);
        d.publish(topic, &[], now).unwrap();
        let contacts: Vec<_> = [
            "192.0.2.1:4000",
            "[::ffff:192.0.2.1]:4001",
            "192.0.2.2:4000",
            "198.51.100.1:4000",
            "203.0.113.1:4000",
        ]
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            Contact::new(
                node_id(Keypair::from_seed(&[i as u8 + 2; 32]).public()),
                addr.parse().unwrap(),
            )
        })
        .collect();
        for c in &contacts {
            d.admit(*c, now);
        }
        d.publication_result(topic, &contacts, now, &mut Vec::new());
        let selected = &d.publications[&topic].owned;
        assert_eq!(selected.len(), 3);
        for index in [0, 3, 4] {
            assert!(selected.contains_key(&contacts[index].id));
        }
        d.publication_result(topic, &contacts[..3], now, &mut Vec::new());
        let selected = &d.publications[&topic].owned;
        assert_eq!(selected.len(), 2);
        assert!(!selected.contains_key(&contacts[1].id));
    }

    #[test]
    fn selection_avoids_duplicate_ips_and_cools_down_failed_registrations() {
        let mut d = Dht::with_routing_policy(
            Keypair::from_seed(&[1; 32]),
            [11; 32],
            false,
            RoutingPolicy::Unrestricted,
        );
        let topic = NodeId::from_bytes([77; 32]);
        let now = Time::new(100_000, 100);
        d.publish(topic, &[], now).unwrap();
        let contacts: Vec<_> = ["192.0.2.2:4000", "192.0.2.2:4001", "192.0.2.3:4000"]
            .iter()
            .enumerate()
            .map(|(i, addr)| {
                Contact::new(
                    node_id(Keypair::from_seed(&[i as u8 + 2; 32]).public()),
                    addr.parse().unwrap(),
                )
            })
            .collect();
        for c in &contacts {
            d.admit(*c, now);
        }
        let mut out = Vec::new();
        d.publication_result(topic, &contacts, now, &mut out);
        assert_eq!(d.publications[&topic].owned.len(), 2);
        assert!(d.publications[&topic].owned.contains_key(&contacts[0].id));
        assert!(!d.publications[&topic].owned.contains_key(&contacts[1].id));
        d.managed
            .get_mut(&(topic, contacts[0].id))
            .unwrap()
            .failures = 2;
        d.publication_result(topic, &contacts, Time::new(130_000, 130), &mut out);
        assert!(!d.publications[&topic].owned.contains_key(&contacts[0].id));
        assert!(d.publications[&topic].owned.contains_key(&contacts[1].id));
        assert_eq!(d.publications[&topic].cooldown[&contacts[0].id], 250_000);
        d.publication_result(topic, &contacts, Time::new(160_000, 160), &mut out);
        assert!(!d.publications[&topic].owned.contains_key(&contacts[0].id));
    }
}
