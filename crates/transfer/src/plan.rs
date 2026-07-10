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

use std::collections::HashSet;

use blob::{Manifest, Store};
use crypto::Hash;

/// Tracks which of a blob's chunks are still needed, hands them out to providers,
/// and reassembles the blob once every chunk has arrived and verified.
pub struct Plan {
    manifest: Manifest,
    /// Distinct chunk hashes not yet handed to a provider. A set, not a queue:
    /// assignment order is decided per round by rarity, not first-seen.
    pending: HashSet<Hash>,
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
        let pending = manifest.chunks.iter().copied().collect();
        let wanted = manifest.chunks.iter().copied().collect();
        Self {
            manifest,
            pending,
            wanted,
            have: Store::new(),
        }
    }

    /// Assign pending chunks to providers for one round, **rarest-first** and
    /// **holdings-aware**. `havesets[i]` is the set of chunk hashes live provider
    /// `i` holds. Chunks are ordered by how few of these providers hold them
    /// (rarest first, so the scarcest data is pulled while its holders are still
    /// around), and each is given to a *least-loaded* provider that actually holds
    /// it, up to `cap` chunks per provider. A chunk no provider holds is left
    /// pending — the swarm can't supply it this round. Assigned chunks are removed
    /// from pending; [`Plan::requeue`] returns any that aren't delivered. The
    /// returned assignment is indexed to match `havesets`.
    ///
    /// Rarest-first is the right default for a partial-seeder swarm (it avoids
    /// piece starvation), but it is *not* ideal for streaming; keeping the choice
    /// to this one ordering makes a future deadline-aware policy a local change.
    pub fn assign(&mut self, havesets: &[&HashSet<Hash>], cap: usize) -> Vec<Vec<Hash>> {
        let mut assignment = vec![Vec::new(); havesets.len()];
        let mut load = vec![0usize; havesets.len()];

        // Rarest-first; ties broken by hash so the schedule is deterministic.
        let holders = |h: &Hash| havesets.iter().filter(|hs| hs.contains(h)).count();
        let mut order: Vec<Hash> = self.pending.iter().copied().collect();
        order.sort_by_key(|h| (holders(h), *h));

        for hash in order {
            let pick = (0..havesets.len())
                .filter(|&i| load[i] < cap && havesets[i].contains(&hash))
                .min_by_key(|&i| (load[i], i));
            if let Some(i) = pick {
                assignment[i].push(hash);
                load[i] += 1;
                self.pending.remove(&hash);
            }
        }
        assignment
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
                self.pending.insert(hash);
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

    /// A haveset holding every chunk — a full seeder.
    fn full(chunks: &[(Hash, Vec<u8>)]) -> HashSet<Hash> {
        chunks.iter().map(|(h, _)| *h).collect()
    }

    /// A haveset holding only the chunks at `indices`.
    fn subset(chunks: &[(Hash, Vec<u8>)], indices: &[usize]) -> HashSet<Hash> {
        indices.iter().map(|&i| chunks[i].0).collect()
    }

    /// Deliver every chunk in `assignment[i]` that provider `i` actually holds.
    fn deliver(plan: &mut Plan, assignment: &[Vec<Hash>], chunks: &[(Hash, Vec<u8>)]) {
        for chunk_list in assignment {
            for h in chunk_list {
                let data = chunks.iter().find(|(ch, _)| ch == h).unwrap().1.clone();
                plan.store(*h, data);
            }
        }
    }

    #[test]
    fn assigns_all_distinct_chunks_then_completes() {
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100);
        let mut plan = Plan::new(manifest);
        let seeder = full(&chunks);

        assert!(!plan.is_complete());
        while plan.pending() > 0 {
            let assignment = plan.assign(&[&seeder], 1); // one chunk per round
            deliver(&mut plan, &assignment, &chunks);
        }
        assert!(plan.is_complete());
        assert_eq!(plan.reassemble().as_deref(), Some(&data[..]));
    }

    #[test]
    fn never_assigns_a_provider_a_chunk_it_lacks() {
        // Three providers with disjoint holdings that together cover the blob.
        let data: Vec<u8> = (0..900u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100); // 9 chunks
        let a = subset(&chunks, &[0, 1, 2]);
        let b = subset(&chunks, &[3, 4, 5]);
        let c = subset(&chunks, &[6, 7, 8]);
        let mut plan = Plan::new(manifest);

        let assignment = plan.assign(&[&a, &b, &c], usize::MAX);
        for (i, held) in [&a, &b, &c].iter().enumerate() {
            for h in &assignment[i] {
                assert!(
                    held.contains(h),
                    "provider {i} was assigned a chunk it lacks"
                );
            }
        }
        // Between them the three cover everything, so one round assigns it all.
        assert_eq!(plan.pending(), 0);
        deliver(&mut plan, &assignment, &chunks);
        assert!(plan.is_complete());
    }

    #[test]
    fn assigns_the_rarest_chunk_to_its_only_holder() {
        // All three providers hold chunks 0, 1, 2; only provider 2 also holds
        // chunk 3 — so chunk 3 is the rarest.
        let data: Vec<u8> = (0..400u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100); // 4 chunks
        let rare = chunks[3].0;
        let common = subset(&chunks, &[0, 1, 2]);
        let a = common.clone();
        let b = common.clone();
        let c = full(&chunks); // holds the rare chunk too
        let mut plan = Plan::new(manifest);

        // Cap 1: each provider gets exactly one chunk this round. The rarest
        // (chunk 3, held only by provider 2) must be the one provider 2 gets.
        let assignment = plan.assign(&[&a, &b, &c], 1);
        assert_eq!(
            assignment[2],
            vec![rare],
            "the sole holder must get the rare chunk"
        );
    }

    #[test]
    fn a_chunk_no_one_holds_stays_pending() {
        let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100); // 3 chunks
                                                   // Providers hold chunks 0 and 1 but nobody holds chunk 2.
        let a = subset(&chunks, &[0]);
        let b = subset(&chunks, &[1]);
        let mut plan = Plan::new(manifest);

        plan.assign(&[&a, &b], usize::MAX);
        // Chunk 2 (held by no one) is the only thing still pending.
        assert_eq!(plan.pending(), 1);
        assert!(plan.pending_contains(chunks[2].0));
        assert!(!plan.is_complete());
    }

    #[test]
    fn cap_bounds_and_balances_per_provider() {
        // Two full seeders, four chunks, cap 1: each gets one this round, the
        // other two stay pending for the next.
        let data: Vec<u8> = (0..400u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100);
        let a = full(&chunks);
        let b = full(&chunks);
        let mut plan = Plan::new(manifest);

        let assignment = plan.assign(&[&a, &b], 1);
        assert_eq!(assignment[0].len(), 1);
        assert_eq!(assignment[1].len(), 1);
        assert_eq!(plan.pending(), 2);
    }

    #[test]
    fn requeued_chunks_are_assigned_again() {
        let data: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100);
        let seeder = full(&chunks);
        let mut plan = Plan::new(manifest);

        // Provider takes everything but delivers nothing (dead); requeue it all.
        let assignment = plan.assign(&[&seeder], usize::MAX);
        assert_eq!(plan.pending(), 0);
        plan.requeue(assignment.into_iter().flatten());
        assert!(plan.pending() > 0);

        // A live seeder now gets them and completes.
        let assignment = plan.assign(&[&seeder], usize::MAX);
        deliver(&mut plan, &assignment, &chunks);
        assert!(plan.is_complete());
        assert_eq!(plan.reassemble().as_deref(), Some(&data[..]));
    }

    #[test]
    fn a_chunk_that_arrived_elsewhere_is_not_requeued() {
        let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100);
        let seeder = full(&chunks);
        let mut plan = Plan::new(manifest);

        let assignment = plan.assign(&[&seeder], usize::MAX);
        // One of the assigned chunks arrives from another provider...
        let (h0, d0) = (chunks[0].0, chunks[0].1.clone());
        assert!(plan.store(h0, d0));
        // ...so requeuing the whole assignment doesn't re-add that one.
        plan.requeue(assignment.into_iter().flatten());
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
        let (manifest, chunks) = blob(&data, 100);
        let seeder = full(&chunks);
        let mut plan = Plan::new(manifest);
        assert_eq!(plan.pending(), 1, "identical chunks dedup to one");
        let assignment = plan.assign(&[&seeder], usize::MAX);
        deliver(&mut plan, &assignment, &chunks);
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
