//! Optional bounded routing liveness, verified replacements, and bucket exploration.
use super::*;

const MAX_CHECKS: usize = 3;
const REPLACEMENTS_PER_BUCKET: usize = 8;
const REFRESH_MARGIN: u64 = 180_000;

/// Address diversity limits for routing contacts, replacements, and lookup candidates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RoutingPolicy {
    /// One identity per IP, two per prefix per bucket, eight per prefix globally.
    /// Lookups allow one candidate per IP, eight per prefix, and sixty-four per seed
    /// referral chain for their lifetime, with scheduling balanced across chains.
    /// Prefixes are IPv4 /24 and IPv6 /64; mapped IPv4 addresses count as IPv4.
    #[default]
    Diverse,
    /// Retain only the normal identity, bucket, and total capacity limits.
    Unrestricted,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Prefix {
    V4([u8; 3]),
    V6([u8; 8]),
}

pub(super) fn network_prefix(addr: SocketAddr) -> Prefix {
    address_group(addr).1
}

fn address_group(addr: SocketAddr) -> (std::net::IpAddr, Prefix) {
    use std::net::IpAddr;
    let ip = match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        ip => ip,
    };
    let prefix = match ip {
        IpAddr::V4(v4) => Prefix::V4(v4.octets()[..3].try_into().unwrap()),
        IpAddr::V6(v6) => Prefix::V6(v6.octets()[..8].try_into().unwrap()),
    };
    (ip, prefix)
}

impl RoutingPolicy {
    pub(super) fn allows_candidate(
        self,
        contact: Contact,
        contacts: impl Iterator<Item = Contact>,
    ) -> bool {
        if self == Self::Unrestricted {
            return true;
        }
        let (ip, prefix) = address_group(contact.addr);
        let mut in_prefix = 0;
        for existing in contacts {
            let (other_ip, other_prefix) = address_group(existing.addr);
            if ip == other_ip {
                return false;
            }
            if prefix == other_prefix {
                in_prefix += 1;
                if in_prefix >= 8 {
                    return false;
                }
            }
        }
        true
    }

    fn allows<'a>(
        self,
        local: NodeId,
        contact: Contact,
        routes: impl Iterator<Item = &'a Route>,
        now: Time,
    ) -> bool {
        if self == Self::Unrestricted {
            return true;
        }
        let (ip, prefix) = address_group(contact.addr);
        let bucket = local.distance(&contact.id).leading_zeros();
        let mut in_prefix = 0;
        let mut in_bucket = 0;
        for route in routes.filter(|r| r.expires > now.monotonic_ms) {
            let (other_ip, other_prefix) = address_group(route.contact.addr);
            if ip == other_ip {
                return false;
            }
            if prefix == other_prefix {
                in_prefix += 1;
                if local.distance(&route.contact.id).leading_zeros() == bucket {
                    in_bucket += 1;
                }
                if in_prefix >= 8 || in_bucket >= 2 {
                    return false;
                }
            }
        }
        true
    }
}

pub(super) struct Maintenance {
    probes: BTreeMap<[u8; 32], Check>,
    replacements: BTreeMap<NodeId, Route>,
    next_at: u64,
    explore_at: u64,
    explore_query: Option<u64>,
    explore_bucket: u16,
}
struct Check {
    contact: Contact,
    observed_expiry: Option<u64>,
}

#[cfg(feature = "test-support")]
impl Maintenance {
    pub(super) fn owns_probe(&self, nonce: &[u8; 32]) -> bool {
        self.probes.contains_key(nonce)
    }
}

impl Dht {
    pub(super) fn routing_allows(&self, contact: Contact, now: Time) -> bool {
        self.routing_policy
            .allows(self.id(), contact, self.routes.values(), now)
    }

    /// Enable background liveness checks, bounded replacements, and bucket exploration.
    /// Callers must continue driving `poll_timeout` and `tick`.
    pub fn maintain_routing(&mut self, now: Time) -> Vec<Action> {
        self.routing.get_or_insert_with(|| Maintenance {
            probes: BTreeMap::new(),
            replacements: BTreeMap::new(),
            next_at: now.monotonic_ms,
            explore_at: now.monotonic_ms.saturating_add(60_000),
            explore_query: None,
            explore_bucket: 0,
        });
        let mut out = Vec::new();
        self.refresh_routes(now, &mut out);
        out
    }

    /// Cancel maintenance-owned probes and lookups. Existing routing contacts remain.
    pub fn stop_routing_maintenance(&mut self) -> bool {
        let Some(state) = self.routing.take() else {
            return false;
        };
        if let Some(query) = state.explore_query {
            self.queries.remove(&query);
            self.pending.retain(|_, p| p.query != Some(query));
        }
        for nonce in state.probes.keys() {
            self.pending.remove(nonce);
        }
        true
    }

    pub(super) fn cache_replacement(&mut self, contact: Contact, now: Time) {
        let id = self.id();
        let Some(state) = self.routing.as_mut() else {
            return;
        };
        let bucket = id.distance(&contact.id).leading_zeros();
        if let Some(old) = state.replacements.get_mut(&contact.id) {
            if old.contact == contact {
                old.expires = now.monotonic_ms.saturating_add(300_000);
            }
        } else if self
            .routing_policy
            .allows(id, contact, state.replacements.values(), now)
            && state.replacements.len() < 256 * REPLACEMENTS_PER_BUCKET
            && state
                .replacements
                .keys()
                .filter(|c| id.distance(c).leading_zeros() == bucket)
                .count()
                < REPLACEMENTS_PER_BUCKET
        {
            state.replacements.insert(
                contact.id,
                Route {
                    contact,
                    expires: now.monotonic_ms.saturating_add(300_000),
                },
            );
        }
    }

    pub(super) fn routing_admitted(&mut self, contact: Contact, now: Time) {
        if let Some(state) = self.routing.as_mut() {
            state.replacements.remove(&contact.id);
            state.next_at = state.next_at.min(now.monotonic_ms.saturating_add(120_000));
        }
    }

    pub(super) fn routing_response(&mut self, nonce: [u8; 32], server: bool) -> bool {
        let Some(state) = self.routing.as_mut() else {
            return false;
        };
        let Some(check) = state.probes.remove(&nonce) else {
            return false;
        };
        if !server {
            if self.routes.get(&check.contact.id).is_some_and(|r| {
                r.contact == check.contact
                    && check.observed_expiry.is_some_and(|old| r.expires <= old)
            }) {
                self.routes.remove(&check.contact.id);
            }
            state.replacements.remove(&check.contact.id);
        }
        state.next_at = 0;
        true
    }

    pub(super) fn routing_failed(&mut self, nonce: [u8; 32]) -> bool {
        let Some(state) = self.routing.as_mut() else {
            return false;
        };
        let Some(check) = state.probes.remove(&nonce) else {
            return false;
        };
        if self.routes.get(&check.contact.id).is_some_and(|r| {
            r.contact == check.contact && check.observed_expiry.is_some_and(|old| r.expires <= old)
        }) {
            self.routes.remove(&check.contact.id);
        }
        if state
            .replacements
            .get(&check.contact.id)
            .is_some_and(|r| r.contact == check.contact)
        {
            state.replacements.remove(&check.contact.id);
        }
        state.next_at = 0;
        true
    }

    pub(super) fn routing_expire(&mut self, now: Time) {
        if let Some(state) = self.routing.as_mut() {
            state
                .replacements
                .retain(|_, r| r.expires > now.monotonic_ms);
        }
    }

    pub(super) fn routing_deadline(&self) -> Option<u64> {
        self.routing
            .as_ref()
            .filter(|s| !self.routes.is_empty() || !s.replacements.is_empty())
            .map(|s| {
                if s.explore_query.is_none() && !self.routes.is_empty() {
                    s.next_at.min(s.explore_at)
                } else {
                    s.next_at
                }
            })
    }

    pub(super) fn routing_query_started(&mut self, query: u64) {
        self.routing
            .as_mut()
            .expect("maintenance enabled")
            .explore_query = Some(query);
    }

    pub(super) fn routing_query_finished(&mut self, now: Time) {
        let jitter = u64::from_le_bytes(
            blake3::keyed_hash(&self.secret, &self.query_serial.to_le_bytes()).as_bytes()[..8]
                .try_into()
                .unwrap(),
        ) % 15_000;
        if let Some(state) = self.routing.as_mut() {
            state.explore_query = None;
            state.explore_at = now.monotonic_ms.saturating_add(60_000 + jitter);
        }
    }

    pub(super) fn explore_routes(&mut self, now: Time, out: &mut Vec<Action>) {
        let Some(state) = self.routing.as_ref() else {
            return;
        };
        if state.explore_query.is_some() || state.explore_at > now.monotonic_ms {
            return;
        }
        let id = self.id();
        let Some(deepest) = self
            .routes
            .values()
            .filter(|r| r.expires > now.monotonic_ms)
            .map(|r| id.distance(&r.contact.id).leading_zeros())
            .max()
        else {
            return;
        };
        if self.queries.len() >= MAX_QUERIES || self.pending.len() >= MAX_PENDING {
            self.routing.as_mut().unwrap().explore_at = now.monotonic_ms.saturating_add(5000);
            return;
        }
        // Cover known distance buckets plus one deeper bucket, then expand if a
        // lookup finds closer nodes. Avoid spending cycles on 256 empty prefixes.
        let width = (deepest + 2).min(256) as u16;
        let bucket = state.explore_bucket % width;
        let target = bucket_target(id, bucket, self.nonce());
        match self.lookup_for(target, &[], QueryOwner::Routing, now) {
            Ok((_, actions)) => {
                out.extend(actions);
                self.routing.as_mut().unwrap().explore_bucket = (bucket + 1) % width;
            }
            Err(_) => {
                self.routing.as_mut().unwrap().explore_at = now.monotonic_ms.saturating_add(5000)
            }
        }
    }

    pub(super) fn refresh_routes(&mut self, now: Time, out: &mut Vec<Action>) {
        let Some(state) = self.routing.as_ref() else {
            return;
        };
        if state.next_at > now.monotonic_ms {
            return;
        }
        let mut buckets = BTreeMap::new();
        let id = self.id();
        for contact in self.routes.keys() {
            *buckets
                .entry(id.distance(contact).leading_zeros())
                .or_insert(0usize) += 1;
        }
        let checking: BTreeSet<_> = state.probes.values().map(|p| p.contact.id).collect();
        let slots = MAX_CHECKS.saturating_sub(state.probes.len());
        let mut candidates: Vec<_> = self
            .routes
            .values()
            .filter(|r| {
                r.expires.saturating_sub(REFRESH_MARGIN) <= now.monotonic_ms
                    && !checking.contains(&r.contact.id)
            })
            .map(|r| (r.expires, r.contact, Some(r.expires)))
            .collect();
        candidates.sort_by_key(|c| c.0);
        candidates.extend(
            state
                .replacements
                .values()
                .filter(|r| {
                    r.expires > now.monotonic_ms
                        && self.routing_allows(r.contact, now)
                        && !checking.contains(&r.contact.id)
                        && buckets
                            .get(&id.distance(&r.contact.id).leading_zeros())
                            .copied()
                            .unwrap_or(0)
                            < K
                })
                .map(|r| (r.expires, r.contact, None)),
        );
        for (_, contact, observed_expiry) in candidates.into_iter().take(slots) {
            if let Ok(nonce) = self.request(contact, Body::Probe, None, now, out) {
                self.routing.as_mut().unwrap().probes.insert(
                    nonce,
                    Check {
                        contact,
                        observed_expiry,
                    },
                );
            }
        }
        let state = self.routing.as_ref().unwrap();
        let checking: BTreeSet<_> = state.probes.values().map(|p| p.contact.id).collect();
        let next = self
            .routes
            .values()
            .filter(|r| !checking.contains(&r.contact.id))
            .map(|r| r.expires.saturating_sub(REFRESH_MARGIN))
            .chain(state.replacements.values().map(|r| {
                if buckets
                    .get(&id.distance(&r.contact.id).leading_zeros())
                    .copied()
                    .unwrap_or(0)
                    < K
                    && !checking.contains(&r.contact.id)
                    && self.routing_allows(r.contact, now)
                {
                    now.monotonic_ms
                } else {
                    r.expires
                }
            }))
            .min()
            .unwrap_or(u64::MAX);
        // Capacity pressure and overdue batches never produce a busy-loop timer.
        self.routing.as_mut().unwrap().next_at = next.max(now.monotonic_ms.saturating_add(1000));
    }
}

fn bucket_target(local: NodeId, bucket: u16, mut distance: [u8; 32]) -> NodeId {
    assert!(bucket < 256);
    let byte = usize::from(bucket / 8);
    let bit = 1u8 << (7 - bucket % 8);
    distance[..byte].fill(0);
    distance[byte] = (distance[byte] & (bit - 1)) | bit;
    for (value, own) in distance.iter_mut().zip(local.as_bytes()) {
        *value ^= own;
    }
    NodeId::from_bytes(distance)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: u64) -> Time {
        Time::new(s * 1000, s)
    }
    fn key(n: u8) -> Keypair {
        Keypair::from_seed(&[n; 32])
    }
    fn addr(n: u8) -> SocketAddr {
        format!("192.0.{n}.1:4000").parse().unwrap()
    }
    fn contact(n: u8) -> Contact {
        Contact::new(node_id(key(n).public()), addr(n))
    }
    fn liveness_only(d: &mut Dht, now: Time) {
        d.maintain_routing(now);
        d.routing.as_mut().unwrap().explore_at = u64::MAX;
    }
    fn core() -> Dht {
        Dht::new(key(1), [101; 32], true)
    }
    fn bucket_peers(d: &Dht) -> Vec<(u8, Contact)> {
        (2..200)
            .map(|n| (n, contact(n)))
            .filter(|(_, c)| d.id().distance(&c.id).leading_zeros() == 0)
            .take(K + 10)
            .collect()
    }
    fn sent(actions: &[Action]) -> Vec<u8> {
        actions
            .iter()
            .find_map(|a| match a {
                Action::Send { bytes, .. } => Some(bytes.clone()),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn authenticated_prefix_flood_bounds_routes_and_replacements() {
        let mut d = core();
        liveness_only(&mut d, at(100));
        let peers = bucket_peers(&d);
        for (n, _) in peers {
            let source = format!("192.0.2.{n}:4000").parse().unwrap();
            let mut peer = Dht::new(key(n), [n; 32], true);
            let opener = sent(&peer.probe(contact(1), at(100)).unwrap());
            let challenge = sent(&d.receive(source, &opener, at(100)));
            let request = sent(&peer.receive(addr(1), &challenge, at(100)));
            let reply = sent(&d.receive(source, &request, at(100)));
            let events = peer.receive(addr(1), &reply, at(100));
            assert!(events
                .iter()
                .any(|a| matches!(a, Action::Event(e) if matches!(**e, Event::Ready(_)))));
            assert!(d.routes.len() <= 2);
            assert!(d.routing.as_ref().unwrap().replacements.len() <= 2);
        }
        assert_eq!(d.routes.len(), 2);
        assert_eq!(d.routing.as_ref().unwrap().replacements.len(), 2);
        assert!(d.tick(at(101)).is_empty());
        assert_eq!(d.poll_timeout(), Some(220_000));
    }

    #[test]
    fn global_prefix_limit_spans_buckets_and_releases_expired_slots() {
        let mut d = core();
        for bucket in 0..9 {
            let c = Contact::new(
                bucket_target(d.id(), bucket, [0; 32]),
                format!("198.51.100.{}:4000", bucket + 1).parse().unwrap(),
            );
            d.admit(c, at(100));
        }
        assert_eq!(d.routes.len(), 8);
        let denied = Contact::new(
            bucket_target(d.id(), 8, [0; 32]),
            "198.51.100.9:4000".parse().unwrap(),
        );
        let first = bucket_target(d.id(), 0, [0; 32]);
        d.routes.get_mut(&first).unwrap().expires = 101_000;
        d.expire(at(101));
        d.admit(denied, at(101));
        assert_eq!(d.routes.len(), 8);
        assert!(d.routes.contains_key(&denied.id));
    }

    #[test]
    fn address_aliases_ports_and_ipv6_interface_ids_cannot_bypass_quotas() {
        let mut d = core();
        let peers = bucket_peers(&d);
        for (i, address) in [
            "192.0.2.1:4000",
            "192.0.2.1:4001",
            "[::ffff:192.0.2.1]:4002",
            "[::ffff:192.0.2.2]:4000",
            "192.0.2.3:4000",
            "[2001:db8:1:1::1]:4000",
            "[2001:db8:1:1::2]:4000",
            "[2001:db8:1:1::3]:4000",
            "[2001:db8:1:2::1]:4000",
        ]
        .iter()
        .enumerate()
        {
            d.admit(
                Contact::new(peers[i].1.id, address.parse().unwrap()),
                at(100),
            );
        }
        assert_eq!(d.routes.len(), 5);
        for i in [0, 3, 5, 6, 8] {
            assert!(d.routes.contains_key(&peers[i].1.id));
        }
        let original = d.routes[&peers[0].1.id].contact;
        d.admit(original, at(110));
        assert_eq!(d.routes[&original.id].expires, 410_000);
        d.admit(
            Contact::new(original.id, "203.0.113.1:4000".parse().unwrap()),
            at(120),
        );
        assert_eq!(d.routes[&original.id].contact, original);
        assert_eq!(d.routes[&original.id].expires, 410_000);
    }

    #[test]
    fn replacement_promotion_rechecks_prefix_capacity_after_probe_started() {
        let mut d = core();
        liveness_only(&mut d, at(100));
        let peers = bucket_peers(&d);
        let contacts: Vec<_> = peers
            .iter()
            .take(4)
            .enumerate()
            .map(|(i, (_, c))| {
                Contact::new(c.id, format!("192.0.2.{}:4000", i + 1).parse().unwrap())
            })
            .collect();
        for c in &contacts[..3] {
            d.admit(*c, at(100));
        }
        d.routes.get_mut(&contacts[0].id).unwrap().expires = 101_000;
        d.routing.as_mut().unwrap().next_at = 101_000;
        let opener = sent(&d.tick(at(101)));
        assert_eq!(d.routes.len(), 1);
        let n = peers[2].0;
        let mut peer = Dht::new(key(n), [n; 32], true);
        let challenge = sent(&peer.receive(addr(1), &opener, at(101)));
        let request = sent(&d.receive(contacts[2].addr, &challenge, at(101)));
        d.admit(contacts[3], at(101));
        let reply = sent(&peer.receive(addr(1), &request, at(101)));
        d.receive(contacts[2].addr, &reply, at(101));
        assert_eq!(d.routes.len(), 2);
        assert!(!d.routes.contains_key(&contacts[2].id));
        assert!(d
            .routing
            .as_ref()
            .unwrap()
            .replacements
            .contains_key(&contacts[2].id));
        d.tick(at(102));
        assert!(d.routing.as_ref().unwrap().probes.is_empty());
        assert!(d.poll_timeout().unwrap() > 102_000);
    }

    #[test]
    fn unrestricted_policy_explicitly_allows_a_private_cluster() {
        let mut d = Dht::with_routing_policy(key(1), [101; 32], true, RoutingPolicy::Unrestricted);
        for (i, (_, c)) in bucket_peers(&d).into_iter().take(K).enumerate() {
            d.admit(
                Contact::new(c.id, format!("127.0.0.1:{}", i + 4000).parse().unwrap()),
                at(100),
            );
        }
        assert_eq!(d.routes.len(), K);
    }

    #[test]
    fn randomized_targets_stay_in_every_requested_distance_bucket() {
        let local = contact(1).id;
        for bucket in 0..256 {
            for entropy in [[0; 32], [255; 32], [73; 32]] {
                let target = bucket_target(local, bucket, entropy);
                assert_eq!(local.distance(&target).leading_zeros(), u32::from(bucket));
            }
        }
        assert_ne!(
            bucket_target(local, 0, [0; 32]),
            bucket_target(local, 0, [255; 32])
        );
    }

    #[test]
    fn exploration_is_single_flight_and_stopping_preserves_application_queries() {
        let mut d = core();
        d.admit(contact(2), at(100));
        d.maintain_routing(at(100));
        assert_eq!(d.poll_timeout(), Some(160_000));
        let actions = d.tick(at(160));
        assert_eq!(actions.len(), 1);
        let owned = d.routing.as_ref().unwrap().explore_query.unwrap();
        assert!(d.queries[&owned].owner == QueryOwner::Routing);
        assert_eq!(
            d.id().distance(&d.queries[&owned].target).leading_zeros(),
            0
        );
        d.tick(Time::new(160_100, 160));
        assert_eq!(d.queries.len(), 1);
        let (application, _) = d.lookup(contact(3).id, &[], at(160)).unwrap();
        assert!(d.stop_routing_maintenance());
        assert!(!d.queries.contains_key(&owned));
        assert!(d.queries.contains_key(&application));
        assert!(d.pending.values().all(|p| p.query == Some(application)));
    }

    #[test]
    fn failed_exploration_has_a_future_retry_without_application_events() {
        let mut d = core();
        d.admit(contact(2), at(100));
        d.maintain_routing(at(100));
        d.tick(at(160));
        let out = d.tick(at(170));
        assert!(out.is_empty());
        let state = d.routing.as_ref().unwrap();
        assert!(state.explore_query.is_none());
        assert!((230_000..245_000).contains(&state.explore_at));
        assert!(d.queries.is_empty());
    }

    #[test]
    fn exploration_defers_at_capacity_and_stays_idle_without_routes() {
        let mut d = core();
        d.maintain_routing(at(100));
        assert_eq!(d.poll_timeout(), None);
        assert!(d.tick(at(160)).is_empty());
        d.admit(contact(2), at(160));
        for _ in 0..MAX_QUERIES {
            d.lookup(contact(3).id, &[], at(160)).unwrap();
        }
        d.tick(at(160));
        let state = d.routing.as_ref().unwrap();
        assert!(state.explore_query.is_none());
        assert_eq!(state.explore_at, 165_000);
        assert_eq!(d.queries.len(), MAX_QUERIES);
    }

    #[test]
    fn full_buckets_keep_bounded_replacements_without_evicting_live_contacts() {
        let mut d = core();
        liveness_only(&mut d, at(100));
        let peers = bucket_peers(&d);
        assert_eq!(peers.len(), K + 10);
        for (_, c) in &peers {
            d.admit(*c, at(100));
        }
        assert_eq!(d.routes.len(), K);
        assert_eq!(
            d.routing.as_ref().unwrap().replacements.len(),
            REPLACEMENTS_PER_BUCKET
        );
        assert!(peers[..K].iter().all(|(_, c)| d.routes.contains_key(&c.id)));
        let actions = d.tick(at(220));
        assert_eq!(actions.len(), MAX_CHECKS);
        assert_eq!(d.routing.as_ref().unwrap().probes.len(), MAX_CHECKS);
        d.tick(Time::new(220_100, 220));
        assert_eq!(d.routing.as_ref().unwrap().probes.len(), MAX_CHECKS);
    }

    #[test]
    fn cached_replacement_requires_fresh_authentication_before_promotion() {
        let mut d = core();
        liveness_only(&mut d, at(100));
        let peers = bucket_peers(&d);
        for (_, c) in peers.iter().take(K + 1) {
            d.admit(*c, at(100));
        }
        d.routes.get_mut(&peers[0].1.id).unwrap().expires = 101_000;
        d.routing.as_mut().unwrap().next_at = 101_000;
        let (n, candidate) = peers[K];
        let mut peer = Dht::new(key(n), [n; 32], true);
        let opener = sent(&d.tick(at(101)));
        assert_eq!(d.routes.len(), K - 1);
        assert!(!d.routes.contains_key(&candidate.id));
        let challenge = sent(&peer.receive(addr(1), &opener, at(101)));
        let request = sent(&d.receive(candidate.addr, &challenge, at(101)));
        assert!(!d.routes.contains_key(&candidate.id));
        let response = sent(&peer.receive(addr(1), &request, at(101)));
        assert!(d.receive(candidate.addr, &response, at(101)).is_empty());
        assert_eq!(d.routes.len(), K);
        assert!(d.routes.contains_key(&candidate.id));
        assert!(!d
            .routing
            .as_ref()
            .unwrap()
            .replacements
            .contains_key(&candidate.id));
    }

    #[test]
    fn a_failed_probe_cannot_erase_newer_authenticated_activity() {
        let mut d = core();
        d.admit(contact(2), at(100));
        liveness_only(&mut d, at(100));
        assert_eq!(d.tick(at(220)).len(), 1);
        d.admit(contact(2), at(221));
        assert!(d.tick(at(229)).is_empty());
        assert_eq!(d.routing_len(), 1);
        assert_eq!(d.poll_timeout(), Some(341_000));
        d.tick(at(341));
        d.tick(at(350));
        assert_eq!(d.routing_len(), 0);
        assert_eq!(d.poll_timeout(), None);
    }

    #[test]
    fn a_peer_that_stops_serving_is_removed_after_a_verified_probe() {
        let mut d = core();
        d.admit(contact(2), at(100));
        liveness_only(&mut d, at(100));
        let mut peer = Dht::new(key(2), [102; 32], false);
        let opener = sent(&d.tick(at(220)));
        let challenge = sent(&peer.receive(addr(1), &opener, at(220)));
        let request = sent(&d.receive(addr(2), &challenge, at(220)));
        let response = sent(&peer.receive(addr(1), &request, at(220)));
        assert!(d.receive(addr(2), &response, at(220)).is_empty());
        assert_eq!(d.routing_len(), 0);
        assert_eq!(d.pending_len(), 0);
        assert_eq!(d.poll_timeout(), None);
    }

    #[test]
    fn stopping_maintenance_preserves_application_probes() {
        let mut d = core();
        d.admit(contact(2), at(100));
        liveness_only(&mut d, at(100));
        d.tick(at(220));
        d.probe(contact(2), at(220)).unwrap();
        assert_eq!(d.pending_len(), 2);
        assert!(d.stop_routing_maintenance());
        assert_eq!(d.pending_len(), 1);
        assert_eq!(d.routing_len(), 1);
        assert!(!d.stop_routing_maintenance());
    }

    #[test]
    fn rpc_capacity_defers_maintenance_without_a_busy_loop() {
        let mut d = core();
        d.admit(contact(2), at(100));
        liveness_only(&mut d, at(100));
        for _ in 0..MAX_PENDING {
            d.probe(contact(3), at(220)).unwrap();
        }
        d.tick(at(220));
        assert!(d.routing.as_ref().unwrap().probes.is_empty());
        assert_eq!(d.routing.as_ref().unwrap().next_at, 221_000);
    }
}

/// Prefer underrepresented IPs, then IPv4 /24 or IPv6 /64 networks. Ties retain
/// caller order (normally XOR distance). Mapped IPv4 shares its native group.
/// Prefixes describe network concentration, not independent operators.
pub fn select_diverse_contact(candidates: &[Contact], selected: &[Contact]) -> Option<Contact> {
    candidates.iter().copied().min_by_key(|candidate| {
        let (ip, prefix) = address_group(candidate.addr);
        let ips = selected
            .iter()
            .filter(|c| address_group(c.addr).0 == ip)
            .count();
        let networks = selected
            .iter()
            .filter(|c| network_prefix(c.addr) == prefix)
            .count();
        (ips, networks)
    })
}

/// Number of IPv4 /24 and IPv6 /64 groups, normalizing mapped IPv4 addresses.
pub fn distinct_networks(contacts: &[Contact]) -> usize {
    contacts
        .iter()
        .map(|c| network_prefix(c.addr))
        .collect::<BTreeSet<_>>()
        .len()
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    fn peer(n: u8, address: &str) -> Contact {
        Contact::new(NodeId::from_bytes([n; 32]), address.parse().unwrap())
    }
    #[test]
    fn diverse_selection_preserves_distance_ties_and_uses_small_network_fallback() {
        let a = peer(1, "192.0.2.1:4000");
        let b = peer(2, "192.0.2.2:4000");
        let c = peer(3, "198.51.100.1:4000");
        let alias = peer(4, "[::ffff:192.0.2.1]:4001");
        assert_eq!(select_diverse_contact(&[a, b, c], &[]), Some(a));
        assert_eq!(select_diverse_contact(&[b, c], &[a]), Some(c));
        assert_eq!(select_diverse_contact(&[alias, b], &[a, c]), Some(b));
        assert_eq!(select_diverse_contact(&[alias], &[a, b, c]), Some(alias));
        assert_eq!(distinct_networks(&[a, b, c, alias]), 2);
    }
    #[test]
    fn ipv6_subnets_and_failed_attempts_do_not_consume_diversity() {
        let a = peer(1, "[2001:db8:1:1::1]:4000");
        let b = peer(2, "[2001:db8:1:1::2]:4000");
        let c = peer(3, "[2001:db8:1:2::1]:4000");
        let d = peer(4, "[2001:db8:1:3::1]:4000");
        assert_eq!(select_diverse_contact(&[b, c, d], &[a]), Some(c));
        // c failed: only a and d are verified. Another candidate in c's
        // network must outrank an extra copy alongside a.
        assert_eq!(select_diverse_contact(&[b, c], &[a, d]), Some(c));
        assert_eq!(distinct_networks(&[a, b, c, d]), 3);
    }
}
