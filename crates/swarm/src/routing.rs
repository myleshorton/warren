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
use std::net::SocketAddr;

/// Bucket capacity — the Kademlia replication parameter.
pub const K: usize = 20;

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

/// A routing table owned by the node with id `local`.
#[derive(Debug)]
pub struct RoutingTable {
    local: NodeId,
    buckets: Vec<Vec<Entry>>,
}

impl RoutingTable {
    /// Create an empty table for the given local id.
    pub fn new(local: NodeId) -> Self {
        Self {
            local,
            buckets: (0..(ID_LEN * 8)).map(|_| Vec::new()).collect(),
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
    /// contact for a full bucket is dropped (keeping older, presumed-live peers)
    /// and `false` is returned.
    pub fn insert(&mut self, contact: Contact) -> bool {
        let Some(idx) = self.bucket_index(&contact.id) else {
            return false;
        };
        let bucket = &mut self.buckets[idx];

        if let Some(pos) = bucket.iter().position(|e| e.contact.id == contact.id) {
            let mut existing = bucket.remove(pos);
            // Refresh address in case it changed, clear any accumulated failures
            // (the peer just proved itself live), then move to the back.
            existing.contact.addr = contact.addr;
            existing.failures = 0;
            bucket.push(existing);
            return true;
        }

        if bucket.len() < K {
            bucket.push(Entry {
                contact,
                failures: 0,
            });
            true
        } else {
            false
        }
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
