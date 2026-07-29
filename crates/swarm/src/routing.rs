//! Kademlia k-bucket routing table.
//!
//! Contacts are filed into 256 buckets by the shared-prefix length between the
//! contact's id and our own. Each bucket holds up to [`K`] contacts,
//! most-recently-seen last, and a full bucket keeps its existing (older,
//! presumed-live) contacts.
//!
//! Departed servers are evicted by a consecutive-failure count: [`record_failure`]
//! bumps a per-contact counter, [`insert`] (a fresh sighting) clears it, and a
//! contact reaching [`EVICTION_THRESHOLD`] failures is dropped. Because any packet
//! from a peer refreshes it, only a peer that is *both* silent and unresponsive
//! across several lookups is removed — a single lost round-trip never evicts.
//!
//! [`record_failure`]: RoutingTable::record_failure
//! [`insert`]: RoutingTable::insert

use crate::id::{NodeId, ID_LEN};
use std::net::{IpAddr, SocketAddr};

/// Bucket capacity — the Kademlia replication parameter.
pub const K: usize = 20;

/// Maximum number of globally-routable contacts from one IPv4 /24 or IPv6 /64
/// in a bucket. Private and loopback addresses are deliberately exempt: they
/// are common in deterministic tests and LAN discovery, and are not an
/// internet eclipse boundary.
pub const MAX_PER_PREFIX: usize = 2;

/// Consecutive unanswered FindNodes (with no intervening packet from the peer)
/// after which a contact is evicted. Three, not one: a lost datagram or a brief
/// blip is transient, and a live server clears its count the moment it sends us
/// anything — so eviction only removes a peer that has genuinely gone away.
pub const EVICTION_THRESHOLD: u8 = 3;

/// A known peer: its id and where to reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    /// The peer's node id.
    pub id: NodeId,
    /// The peer's socket address.
    pub addr: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicPrefix {
    V4([u8; 3]),
    V6([u8; 8]),
}

fn public_prefix(ip: IpAddr) -> Option<PublicPrefix> {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            if ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || octets[0] == 0
            {
                None
            } else {
                Some(PublicPrefix::V4([octets[0], octets[1], octets[2]]))
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
            {
                None
            } else {
                let octets = ip.octets();
                Some(PublicPrefix::V6([
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
                    octets[7],
                ]))
            }
        }
    }
}

impl Contact {
    /// Create a contact.
    pub fn new(id: NodeId, addr: SocketAddr) -> Self {
        Self { id, addr }
    }
}

/// A stored contact plus its liveness bookkeeping. The failure counter is
/// table-internal — `closest`/`contains` hand callers bare [`Contact`]s, so it
/// never leaks into query results or the `Nodes` wire message.
#[derive(Clone, Copy, Debug)]
struct Entry {
    contact: Contact,
    /// Consecutive unanswered FindNodes; reset to 0 by any fresh sighting.
    failures: u8,
}

/// Result of attempting to admit a routing contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Inserted,
    Refreshed,
    /// The candidate is retained in a bounded replacement cache; the caller
    /// should ping the least-recently-seen incumbent before replacing it.
    Probe(Contact),
    Rejected,
}

/// A routing table owned by the node with id `local`.
#[derive(Debug)]
pub struct RoutingTable {
    local: NodeId,
    buckets: Vec<Vec<Entry>>,
    replacements: Vec<Vec<Contact>>,
}

impl RoutingTable {
    /// Create an empty table for the given local id.
    pub fn new(local: NodeId) -> Self {
        Self {
            local,
            buckets: (0..(ID_LEN * 8)).map(|_| Vec::new()).collect(),
            replacements: (0..(ID_LEN * 8)).map(|_| Vec::new()).collect(),
        }
    }

    fn bucket_index(&self, id: &NodeId) -> Option<usize> {
        let d = self.local.distance(id);
        let lz = d.leading_zeros() as usize;
        // lz == 256 means id == local; we never store ourselves.
        if lz >= ID_LEN * 8 {
            None
        } else {
            Some(lz)
        }
    }

    /// Insert or refresh a contact.
    ///
    /// Returns `true` if the contact is now present. A contact already known is
    /// moved to the most-recently-seen position, its address refreshed, and its
    /// failure count cleared — a fresh sighting is proof the peer is live. A new
    /// contact for a full bucket is retained in the replacement cache and
    /// `false` is returned; callers that need liveness probing should use
    /// [`admit`].
    pub fn insert(&mut self, contact: Contact) -> bool {
        matches!(
            self.admit(contact),
            Admission::Inserted | Admission::Refreshed
        )
    }

    /// Admit or refresh a contact while retaining a bounded replacement
    /// candidate for a full bucket. The actual LRU ping is driven by the DHT,
    /// which owns request IDs and timeouts.
    pub fn admit(&mut self, contact: Contact) -> Admission {
        let Some(idx) = self.bucket_index(&contact.id) else {
            return Admission::Rejected;
        };
        let prefix_allowed = self.prefix_allowed(idx, contact.addr);
        let bucket = &mut self.buckets[idx];

        if let Some(pos) = bucket.iter().position(|e| e.contact.id == contact.id) {
            let mut existing = bucket.remove(pos);
            // Refresh address in case it changed, clear any accumulated failures
            // (the peer just proved itself live), then move to the back.
            existing.contact.addr = contact.addr;
            existing.failures = 0;
            bucket.push(existing);
            self.replacements[idx].retain(|c| c.id != contact.id);
            return Admission::Refreshed;
        }

        if bucket.len() < K && prefix_allowed {
            bucket.push(Entry {
                contact,
                failures: 0,
            });
            Admission::Inserted
        } else if bucket.len() == K {
            let replacements = &mut self.replacements[idx];
            replacements.retain(|c| c.id != contact.id);
            replacements.push(contact);
            if replacements.len() > K {
                replacements.remove(0);
            }
            bucket
                .first()
                .map(|entry| Admission::Probe(entry.contact))
                .unwrap_or(Admission::Rejected)
        } else {
            // Diversity is an admission rule, not a reason to evict an
            // unrelated live peer. This candidate cannot currently occupy a
            // slot, so do not retain it as a replacement.
            Admission::Rejected
        }
    }

    fn prefix_allowed(&self, bucket: usize, addr: SocketAddr) -> bool {
        let Some(prefix) = public_prefix(addr.ip()) else {
            return true;
        };
        self.buckets[bucket]
            .iter()
            .filter(|entry| public_prefix(entry.contact.addr.ip()) == Some(prefix))
            .count()
            < MAX_PER_PREFIX
    }

    /// Remove an unresponsive contact and promote the most-recent admissible
    /// replacement. Returns the promoted contact, if any.
    pub fn replace_unresponsive(&mut self, id: &NodeId) -> Option<Contact> {
        let idx = self.bucket_index(id)?;
        let pos = self.buckets[idx]
            .iter()
            .position(|entry| entry.contact.id == *id)?;
        self.buckets[idx].remove(pos);
        while let Some(candidate) = self.replacements[idx].pop() {
            if self.prefix_allowed(idx, candidate.addr) {
                self.buckets[idx].push(Entry {
                    contact: candidate,
                    failures: 0,
                });
                return Some(candidate);
            }
        }
        None
    }

    /// Record that a request to `id` went unanswered.
    ///
    /// Increments the contact's consecutive-failure count; if that reaches
    /// [`EVICTION_THRESHOLD`] the contact is removed and `true` is returned.
    /// An unknown id is a no-op returning `false`. A subsequent [`insert`] (any
    /// fresh sighting) resets the count, so only *sustained* silence evicts.
    ///
    /// [`insert`]: RoutingTable::insert
    pub fn record_failure(&mut self, id: &NodeId) -> bool {
        let Some(idx) = self.bucket_index(id) else {
            return false;
        };
        let bucket = &mut self.buckets[idx];
        let Some(pos) = bucket.iter().position(|e| e.contact.id == *id) else {
            return false;
        };
        bucket[pos].failures = bucket[pos].failures.saturating_add(1);
        if bucket[pos].failures >= EVICTION_THRESHOLD {
            bucket.remove(pos);
            while let Some(candidate) = self.replacements[idx].pop() {
                if self.prefix_allowed(idx, candidate.addr) {
                    self.buckets[idx].push(Entry {
                        contact: candidate,
                        failures: 0,
                    });
                    break;
                }
            }
            true
        } else {
            false
        }
    }

    /// Whether a contact with this id is present.
    pub fn contains(&self, id: &NodeId) -> bool {
        match self.bucket_index(id) {
            Some(idx) => self.buckets[idx].iter().any(|e| e.contact.id == *id),
            None => false,
        }
    }

    /// Total number of contacts across all buckets.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    /// Whether the table holds no contacts.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `n` contacts closest to `target`, nearest first.
    pub fn closest(&self, target: &NodeId, n: usize) -> Vec<Contact> {
        let mut all: Vec<Contact> = self.buckets.iter().flatten().map(|e| e.contact).collect();
        all.sort_by_key(|c| c.id.distance(target));
        all.truncate(n);
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn id(first: u8) -> NodeId {
        let mut b = [0u8; ID_LEN];
        b[0] = first;
        NodeId::from_bytes(b)
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    fn public_addr(host: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(host), port))
    }

    #[test]
    fn does_not_store_self() {
        let me = id(0x01);
        let mut t = RoutingTable::new(me);
        assert!(!t.insert(Contact::new(me, addr(1))));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn insert_and_contains() {
        let mut t = RoutingTable::new(id(0x00));
        let c = Contact::new(id(0x42), addr(1));
        assert!(t.insert(c));
        assert!(t.contains(&id(0x42)));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn reinsert_refreshes_address_not_count() {
        let mut t = RoutingTable::new(id(0x00));
        assert!(t.insert(Contact::new(id(0x42), addr(1))));
        assert!(t.insert(Contact::new(id(0x42), addr(2))));
        assert_eq!(t.len(), 1);
        let c = t.closest(&id(0x42), 1);
        assert_eq!(c[0].addr, addr(2));
    }

    #[test]
    fn closest_returns_nearest_first() {
        let mut t = RoutingTable::new(id(0x00));
        for b in [0x01u8, 0x02, 0x04, 0x08, 0x80, 0xff] {
            t.insert(Contact::new(id(b), addr(b as u16)));
        }
        let got = t.closest(&id(0x00), 3);
        assert_eq!(got.len(), 3);
        // Distances to 0x00 are the ids themselves; nearest is 0x01.
        assert_eq!(got[0].id, id(0x01));
        assert_eq!(got[1].id, id(0x02));
        assert_eq!(got[2].id, id(0x04));
    }

    #[test]
    fn full_bucket_keeps_existing_contacts() {
        // To land many contacts in one bucket they must share a prefix length
        // with local. Local is all-zero; setting the top bit (byte0 = 0x80)
        // makes the XOR distance have zero leading zeros, so every such contact
        // falls in bucket 0. We then vary a later byte to make distinct ids.
        let mut t = RoutingTable::new(NodeId::from_bytes([0u8; ID_LEN]));
        let mut inserted = Vec::new();
        for i in 1..=(K as u16 + 5) {
            let mut b = [0u8; ID_LEN];
            b[0] = 0x80;
            b[1] = i as u8;
            let c = Contact::new(NodeId::from_bytes(b), addr(i));
            if t.insert(c) {
                inserted.push(c.id);
            }
        }
        // Exactly K land in that single bucket; the rest are rejected.
        assert_eq!(t.len(), K);
        assert_eq!(inserted.len(), K);
        // The first K inserted are the retained ones.
        for retained in &inserted {
            assert!(t.contains(retained));
        }
    }

    #[test]
    fn full_bucket_keeps_bounded_replacement_and_names_lru_for_probe() {
        let mut t = RoutingTable::new(NodeId::from_bytes([0u8; ID_LEN]));
        let mut first = None;
        for i in 1..=K {
            let mut b = [0u8; ID_LEN];
            b[0] = 0x80;
            b[1] = i as u8;
            let c = Contact::new(NodeId::from_bytes(b), addr(i as u16));
            if i == 1 {
                first = Some(c);
            }
            assert_eq!(t.admit(c), Admission::Inserted);
        }
        let mut b = [0u8; ID_LEN];
        b[0] = 0x80;
        b[1] = 99;
        let candidate = Contact::new(NodeId::from_bytes(b), addr(99));
        assert_eq!(t.admit(candidate), Admission::Probe(first.unwrap()));
        assert_eq!(t.replace_unresponsive(&first.unwrap().id), Some(candidate));
        assert!(!t.contains(&first.unwrap().id));
        assert!(t.contains(&candidate.id));
    }

    #[test]
    fn limits_public_v4_prefixes_but_not_private_test_addresses() {
        let mut t = RoutingTable::new(id(0));
        for i in 1..=MAX_PER_PREFIX {
            let mut b = [0u8; ID_LEN];
            b[0] = 0x40;
            b[1] = i as u8;
            assert_eq!(
                t.admit(Contact::new(
                    NodeId::from_bytes(b),
                    public_addr([8, 8, 8, i as u8], i as u16)
                )),
                Admission::Inserted
            );
        }
        let mut b = [0u8; ID_LEN];
        b[0] = 0x40;
        b[1] = 99;
        assert_eq!(
            t.admit(Contact::new(
                NodeId::from_bytes(b),
                public_addr([8, 8, 8, 99], 99)
            )),
            Admission::Rejected
        );
        assert_eq!(t.len(), MAX_PER_PREFIX);

        // Private/LAN contacts are intentionally exempt from this public
        // internet eclipse guard.
        b[1] = 100;
        assert_eq!(
            t.admit(Contact::new(NodeId::from_bytes(b), addr(100))),
            Admission::Inserted
        );
    }

    #[test]
    fn failures_below_threshold_retain_contact() {
        let mut t = RoutingTable::new(id(0x00));
        let c = Contact::new(id(0x42), addr(1));
        t.insert(c);
        for _ in 0..(EVICTION_THRESHOLD - 1) {
            assert!(
                !t.record_failure(&c.id),
                "should not evict before threshold"
            );
        }
        assert!(t.contains(&c.id));
    }

    #[test]
    fn sustained_failures_evict() {
        let mut t = RoutingTable::new(id(0x00));
        let c = Contact::new(id(0x42), addr(1));
        t.insert(c);
        let mut evicted = false;
        for _ in 0..EVICTION_THRESHOLD {
            evicted = t.record_failure(&c.id);
        }
        assert!(evicted, "the threshold-th failure returns true");
        assert!(!t.contains(&c.id), "the departed contact is gone");
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn success_resets_failure_count() {
        // A live-but-lossy server: it accumulates failures, but a single fresh
        // sighting between them clears the count, so it is never evicted.
        let mut t = RoutingTable::new(id(0x00));
        let c = Contact::new(id(0x42), addr(1));
        t.insert(c);
        for _ in 0..(EVICTION_THRESHOLD - 1) {
            t.record_failure(&c.id);
        }
        t.insert(c); // a packet arrives — proof of life, resets the counter
        for _ in 0..(EVICTION_THRESHOLD - 1) {
            assert!(!t.record_failure(&c.id));
        }
        assert!(
            t.contains(&c.id),
            "reset means the second failure run also stays below threshold"
        );
    }

    #[test]
    fn record_failure_unknown_id_is_noop() {
        let mut t = RoutingTable::new(id(0x00));
        assert!(!t.record_failure(&id(0x99)));
        assert_eq!(t.len(), 0);
    }
}
