//! Scheduling for a multi-provider (swarm) blob download.
//!
//! A blob is content-addressed: each chunk is named by its BLAKE3 hash, so a
//! chunk fetched from *any* provider is verified the same way and any provider
//! holding it is interchangeable. That's what makes swarming work — this module
//! is the bookkeeping that hands distinct chunks out to providers, folds in the
//! ones that come back verified, takes back the ones that don't, and knows when
//! the blob is whole.
//!
//! It is **sans-IO**: no sockets, no tasks. The driver ([`download_blob_swarm`](crate))
//! connects to providers and runs the fetches; this decides *what* to fetch and
//! tracks progress, so the assignment/re-assignment logic is unit-tested on its
//! own.

use std::collections::{HashSet, VecDeque};

use blob::{Manifest, Store};
use crypto::Hash;

/// Tracks which of a blob's chunks are still needed, hands them out to providers,
/// and reassembles the blob once every chunk has arrived and verified.
pub struct Plan {
    manifest: Manifest,
    /// Distinct chunk hashes not yet handed to a provider, in first-seen order.
    pending: VecDeque<Hash>,
    /// The distinct chunks the blob is made of — for membership (a provider can't
    /// slip us a chunk that isn't part of this blob) and for completion.
    wanted: HashSet<Hash>,
    /// Chunks received and verified, keyed by hash (dedup'd — identical chunks
    /// share a hash and are fetched once).
    have: Store,
}

impl Plan {
    /// Begin from a verified manifest. Chunks already present would be skipped,
    /// but a fresh plan starts with an empty store, so every distinct chunk is
    /// pending.
    pub fn new(manifest: Manifest) -> Self {
        let mut seen = HashSet::new();
        let pending = manifest
            .chunks
            .iter()
            .filter(|h| seen.insert(**h))
            .copied()
            .collect();
        let wanted = manifest.chunks.iter().copied().collect();
        Self {
            manifest,
            pending,
            wanted,
            have: Store::new(),
        }
    }

    /// Take up to `n` chunks to assign to one provider, removing them from the
    /// pending queue. Fewer than `n` (or none) when little/nothing is left.
    pub fn take(&mut self, n: usize) -> Vec<Hash> {
        let count = n.min(self.pending.len());
        self.pending.drain(..count).collect()
    }

    /// Fold in a chunk a provider delivered. The bytes must hash to `hash` and
    /// `hash` must belong to this blob; otherwise it's ignored (a provider can't
    /// inject data that isn't part of the content address it claims to serve).
    /// Returns whether it was accepted as new progress.
    pub fn store(&mut self, hash: Hash, data: Vec<u8>) -> bool {
        if !self.wanted.contains(&hash) || self.have.has(&hash) {
            return false;
        }
        if crypto::hash(&data) != hash {
            return false;
        }
        self.have.put_hashed(hash, data);
        true
    }

    /// Return chunks a provider was assigned but didn't deliver, so another
    /// provider can be given them. Ones that have since arrived (from elsewhere)
    /// are dropped rather than re-queued.
    pub fn requeue(&mut self, hashes: impl IntoIterator<Item = Hash>) {
        for hash in hashes {
            if self.wanted.contains(&hash) && !self.have.has(&hash) {
                self.pending.push_back(hash);
            }
        }
    }

    /// Distinct chunks still waiting to be assigned.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Whether every distinct chunk has arrived and verified.
    pub fn is_complete(&self) -> bool {
        self.wanted.iter().all(|h| self.have.has(h))
    }

    /// Reassemble the blob, or `None` if not yet complete.
    pub fn reassemble(&self) -> Option<Vec<u8>> {
        self.have.reassemble(&self.manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest + its chunks for `data`, split at `chunk_size`.
    fn blob(data: &[u8], chunk_size: usize) -> (Manifest, Vec<(Hash, Vec<u8>)>) {
        let (manifest, chunks) = blob::split_with(data, chunk_size);
        let pairs = manifest.chunks.iter().copied().zip(chunks).collect();
        (manifest, pairs)
    }

    #[test]
    fn assigns_all_distinct_chunks_then_completes() {
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100);
        let mut plan = Plan::new(manifest);

        // Hand every chunk out (one at a time), store each: completes exactly once.
        assert!(!plan.is_complete());
        let mut handed = 0;
        while plan.pending() > 0 {
            for h in plan.take(1) {
                let data = chunks.iter().find(|(ch, _)| *ch == h).unwrap().1.clone();
                assert!(plan.store(h, data));
                handed += 1;
            }
        }
        assert!(plan.is_complete());
        assert_eq!(plan.reassemble().as_deref(), Some(&data[..]));
        assert!(handed >= 10);
    }

    #[test]
    fn requeued_chunks_are_handed_out_again() {
        let data: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100);
        let mut plan = Plan::new(manifest);

        // Provider A takes everything but delivers nothing (dead); requeue it all.
        let assigned = plan.take(usize::MAX);
        assert_eq!(plan.pending(), 0);
        plan.requeue(assigned);
        assert!(plan.pending() > 0);

        // Provider B now gets them and completes.
        for h in plan.take(usize::MAX) {
            let data = chunks.iter().find(|(ch, _)| *ch == h).unwrap().1.clone();
            plan.store(h, data);
        }
        assert!(plan.is_complete());
        assert_eq!(plan.reassemble().as_deref(), Some(&data[..]));
    }

    #[test]
    fn a_chunk_that_arrived_elsewhere_is_not_requeued() {
        let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100);
        let mut plan = Plan::new(manifest);

        let assigned = plan.take(usize::MAX);
        // One of the assigned chunks arrives from another provider...
        let (h0, d0) = (chunks[0].0, chunks[0].1.clone());
        assert!(plan.store(h0, d0));
        // ...so requeuing the whole assignment doesn't re-add that one.
        plan.requeue(assigned.iter().copied());
        assert!(!plan.pending_contains(h0));
    }

    #[test]
    fn rejects_junk_and_foreign_chunks() {
        let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100);
        let real = chunks[0].0;
        let mut plan = Plan::new(manifest);

        // Wrong bytes for a real hash: rejected.
        assert!(!plan.store(real, b"not the chunk".to_vec()));
        // A hash that isn't part of the blob: rejected even if self-consistent.
        let foreign = crypto::hash(b"foreign");
        assert!(!plan.store(foreign, b"foreign".to_vec()));
        assert!(!plan.is_complete());
    }

    #[test]
    fn duplicate_chunks_are_fetched_once() {
        // A blob of three identical chunks: the manifest lists one hash thrice,
        // so only one distinct chunk is ever pending.
        let data = vec![0x5au8; 300];
        let (manifest, _) = blob(&data, 100);
        let mut plan = Plan::new(manifest);
        assert_eq!(plan.pending(), 1, "identical chunks dedup to one");
        for h in plan.take(usize::MAX) {
            plan.store(h, vec![0x5au8; 100]);
        }
        assert!(plan.is_complete());
        assert_eq!(plan.reassemble(), Some(data));
    }

    impl Plan {
        /// Test helper: is `hash` currently pending?
        fn pending_contains(&self, hash: Hash) -> bool {
            self.pending.contains(&hash)
        }
    }
}
