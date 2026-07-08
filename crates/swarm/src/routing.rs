//! Kademlia k-bucket routing table.
//!
//! Contacts are filed into 256 buckets by the shared-prefix length between the
//! contact's id and our own. Each bucket holds up to [`K`] contacts,
//! most-recently-seen last. This is the structure the ephemeral/persistent
//! lifecycle and eviction policy will later hook into; for now a full bucket
//! simply keeps its existing (older, presumed-live) contacts.

use crate::id::{NodeId, ID_LEN};
use std::net::SocketAddr;

/// Bucket capacity — the Kademlia replication parameter.
pub const K: usize = 20;

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

/// A routing table owned by the node with id `local`.
#[derive(Debug)]
pub struct RoutingTable {
    local: NodeId,
    buckets: Vec<Vec<Contact>>,
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
    /// moved to the most-recently-seen position. A new contact for a full bucket
    /// is dropped (keeping older, presumed-live peers) and `false` is returned.
    pub fn insert(&mut self, contact: Contact) -> bool {
        let Some(idx) = self.bucket_index(&contact.id) else {
            return false;
        };
        let bucket = &mut self.buckets[idx];

        if let Some(pos) = bucket.iter().position(|c| c.id == contact.id) {
            let existing = bucket.remove(pos);
            // Refresh address in case it changed, then move to the back.
            bucket.push(Contact {
                id: existing.id,
                addr: contact.addr,
            });
            return true;
        }

        if bucket.len() < K {
            bucket.push(contact);
            true
        } else {
            false
        }
    }

    /// Whether a contact with this id is present.
    pub fn contains(&self, id: &NodeId) -> bool {
        match self.bucket_index(id) {
            Some(idx) => self.buckets[idx].iter().any(|c| c.id == *id),
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
        let mut all: Vec<Contact> = self.buckets.iter().flatten().copied().collect();
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
}
