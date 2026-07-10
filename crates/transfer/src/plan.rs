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

use std::collections::{HashMap, HashSet};

use blob::{Manifest, Store};
use crypto::Hash;

/// How [`Plan::assign`] orders the pending chunks it hands out.
#[derive(Clone, Copy, Debug, Default)]
pub enum Selection {
    /// Fewest-known-holders first — maximizes piece availability across the
    /// swarm. The right default for a bulk download.
    #[default]
    RarestFirst,
    /// For streaming playback: fetch the chunks nearest the playback frontier (the
    /// `window` lowest playback positions) *in playback order*, so a player can
    /// start and keep going; beyond the window, fall back to rarest-first for
    /// swarm health.
    Streaming {
        /// How many chunks ahead of the playback frontier to fetch in order.
        window: usize,
    },
}

/// What a provider can serve, as far as the scheduler knows — the input to
/// [`Plan::assign`].
#[derive(Clone, Debug)]
pub enum Holdings {
    /// The provider reported holding exactly these chunks (a `Have` bitfield).
    Known(HashSet<Hash>),
    /// The provider couldn't report its holdings, so it might hold anything —
    /// except the chunks it has since *refused* (answered `Absent` to). Used only
    /// as a *last resort*, after known holders, so a speculative provider can
    /// never be handed the last copy of a chunk while a provider known to have it
    /// sits idle.
    Unknown(HashSet<Hash>),
}

impl Holdings {
    /// An `Unknown` provider that has refused nothing yet.
    pub fn unknown() -> Self {
        Holdings::Unknown(HashSet::new())
    }

    /// Record that this provider won't serve `hash` after all — it was asked for
    /// it but didn't return it (an `Absent`, an unexpected reply, or a chunk that
    /// failed verification). A known holder drops it from its set (a stale or
    /// dishonest bitfield); an unknown provider remembers the refusal. Either way
    /// [`Plan::assign`] won't offer this provider that chunk again, which is what
    /// keeps a work-stealing loop from re-handing a chunk to a provider that
    /// already refused it.
    pub fn refuse(&mut self, hash: &Hash) {
        match self {
            Holdings::Known(set) => {
                set.remove(hash);
            }
            Holdings::Unknown(refused) => {
                refused.insert(*hash);
            }
        }
    }

    /// Whether this provider might serve `hash`: a known holder that has it, or an
    /// `Unknown` provider that hasn't refused it.
    fn can_serve(&self, hash: &Hash) -> bool {
        match self {
            Holdings::Known(set) => set.contains(hash),
            Holdings::Unknown(refused) => !refused.contains(hash),
        }
    }

    /// Whether this provider is a speculative (unknown-holdings) source.
    fn is_unknown(&self) -> bool {
        matches!(self, Holdings::Unknown(_))
    }

    /// Whether this is a *known* holder of `hash`. An `Unknown` provider is not a
    /// known holder — it doesn't count toward a chunk's rarity.
    fn is_known_holder(&self, hash: &Hash) -> bool {
        matches!(self, Holdings::Known(set) if set.contains(hash))
    }
}

/// Tracks which of a blob's chunks are still needed, hands them out to providers,
/// and reassembles the blob once every chunk has arrived and verified.
pub struct Plan {
    manifest: Manifest,
    /// Distinct chunk hashes not yet handed to a provider. A set, not a queue:
    /// assignment order is decided per round by the [`Selection`] policy.
    pending: HashSet<Hash>,
    /// The distinct chunks the blob is made of — for membership (a provider can't
    /// slip us a chunk that isn't part of this blob) and for completion.
    wanted: HashSet<Hash>,
    /// Earliest manifest index each distinct chunk appears at — its playback
    /// position, for the streaming selection policy.
    positions: HashMap<Hash, usize>,
    /// Latest manifest index each distinct chunk appears at — so a deduplicated
    /// chunk (shared by several positions) is dropped only after its *last* one
    /// has been delivered.
    last_positions: HashMap<Hash, usize>,
    /// Chunks received and verified, keyed by hash (dedup'd — identical chunks
    /// share a hash and are fetched once).
    have: Store,
    /// How pending chunks are ordered when handed out.
    selection: Selection,
    /// Next playback index to deliver. Streaming fetches within a window ahead of
    /// this and drops chunks behind it; it also marks completion (all delivered).
    frontier: usize,
}

impl Plan {
    /// Begin from a verified manifest. Chunks already present would be skipped,
    /// but a fresh plan starts with an empty store, so every distinct chunk is
    /// pending. Defaults to [`Selection::RarestFirst`].
    pub fn new(manifest: Manifest) -> Self {
        let pending = manifest.chunks.iter().copied().collect();
        let wanted = manifest.chunks.iter().copied().collect();
        let mut positions = HashMap::new();
        let mut last_positions = HashMap::new();
        for (i, hash) in manifest.chunks.iter().enumerate() {
            positions.entry(*hash).or_insert(i); // earliest index = playback position
            last_positions.insert(*hash, i); // last write wins = latest index
        }
        Self {
            manifest,
            pending,
            wanted,
            positions,
            last_positions,
            have: Store::new(),
            selection: Selection::default(),
            frontier: 0,
        }
    }

    /// Choose how [`assign`](Self::assign) orders the pending chunks it hands out.
    pub fn set_selection(&mut self, selection: Selection) {
        self.selection = selection;
    }

    /// Assign pending chunks to providers for one round, **holdings-aware**.
    /// `holdings[i]` is what live provider `i` can serve. Chunks are considered in
    /// the order set by the current [`Selection`] (see [`ordered_pending`](Self::ordered_pending)
    /// — rarest-first by default, playback-order for streaming) and each is given
    /// to a *least-loaded* provider that can serve it, up to `cap` chunks per
    /// provider. A known holder is always preferred over a [`Holdings::Unknown`]
    /// provider, so the last copy of a chunk is never wasted on a speculative
    /// source while a known holder is idle. A chunk no one can serve is left
    /// pending. Assigned chunks are removed from pending; [`Plan::requeue`]
    /// returns any that aren't delivered. The result is indexed to match `holdings`.
    pub fn assign(&mut self, holdings: &[&Holdings], cap: usize) -> Vec<Vec<Hash>> {
        let mut assignment = vec![Vec::new(); holdings.len()];
        let mut load = vec![0usize; holdings.len()];

        for hash in self.ordered_pending(holdings) {
            // Prefer a known holder over a speculative Unknown (`is_unknown`:
            // false sorts first), then least-loaded, then lowest index.
            let pick = (0..holdings.len())
                .filter(|&i| load[i] < cap && holdings[i].can_serve(&hash))
                .min_by_key(|&i| (holdings[i].is_unknown(), load[i], i));
            if let Some(i) = pick {
                assignment[i].push(hash);
                load[i] += 1;
                self.pending.remove(&hash);
            }
        }
        assignment
    }

    /// The pending chunks in the order [`assign`](Self::assign) should hand them
    /// out, per the current [`Selection`]. Rarity counts only *known* holders — a
    /// speculative Unknown provider doesn't make a chunk look less scarce.
    /// `sort_by_cached_key` computes each key once.
    fn ordered_pending(&self, holdings: &[&Holdings]) -> Vec<Hash> {
        let known_holders = |h: &Hash| holdings.iter().filter(|hd| hd.is_known_holder(h)).count();
        let mut order: Vec<Hash> = self.pending.iter().copied().collect();
        match self.selection {
            // Rarest first; ties by hash so the schedule is deterministic.
            Selection::RarestFirst => order.sort_by_cached_key(|h| (known_holders(h), *h)),
            // A bounded sliding window: only fetch chunks within `window` playback
            // positions of the frontier, in playback order — so memory stays
            // bounded (nothing far ahead is fetched) and the frontier, which
            // delivery blocks on, is filled first. Chunks beyond the window aren't
            // returned, so they aren't fetched until the frontier advances.
            Selection::Streaming { window } => {
                let cutoff = self.frontier.saturating_add(window);
                order.retain(|h| self.positions[h] < cutoff);
                order.sort_by_cached_key(|h| self.positions[h]);
            }
        }
        order
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

    /// Whether every distinct chunk has arrived and verified. The running download
    /// tracks completion by *delivery* ([`all_delivered`](Self::all_delivered)),
    /// since streaming drops delivered chunks; this storage-based view is used by
    /// the unit tests, which store without delivering.
    #[cfg(test)]
    pub fn is_complete(&self) -> bool {
        self.wanted.iter().all(|h| self.have.has(h))
    }

    /// Reassemble the blob, or `None` if not yet complete.
    pub fn reassemble(&self) -> Option<Vec<u8>> {
        self.have.reassemble(&self.manifest)
    }

    /// How many chunks the blob has, in playback order (counting repeats).
    pub fn chunk_count(&self) -> usize {
        self.manifest.chunks.len()
    }

    /// The verified bytes of the chunk at playback `index`, if it has been stored
    /// yet — for delivering a blob to a streaming consumer in order.
    pub fn chunk_at(&self, index: usize) -> Option<&[u8]> {
        self.have.get(self.manifest.chunks.get(index)?)
    }

    /// The next playback index not yet delivered — the frontier the streaming
    /// window is measured from, and delivery blocks on.
    pub fn frontier(&self) -> usize {
        self.frontier
    }

    /// Whether every playback index has been delivered.
    pub fn all_delivered(&self) -> bool {
        self.frontier >= self.chunk_count()
    }

    /// Record that the chunk at the frontier has been delivered: advance the
    /// frontier and, when `drop_delivered` is set (streaming), free the chunk's
    /// bytes once its *last* playback position has passed — so a deduplicated
    /// chunk still lasts until the later index, but memory stays bounded.
    pub fn advance_delivery(&mut self, drop_delivered: bool) {
        let index = self.frontier;
        self.frontier += 1;
        if drop_delivered {
            if let Some(&hash) = self.manifest.chunks.get(index) {
                if self.last_positions.get(&hash) == Some(&index) {
                    self.have.remove(&hash);
                }
            }
        }
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

    /// Known holdings of every chunk — a full seeder.
    fn full(chunks: &[(Hash, Vec<u8>)]) -> Holdings {
        Holdings::Known(chunks.iter().map(|(h, _)| *h).collect())
    }

    /// Known holdings of only the chunks at `indices`.
    fn subset(chunks: &[(Hash, Vec<u8>)], indices: &[usize]) -> Holdings {
        Holdings::Known(indices.iter().map(|&i| chunks[i].0).collect())
    }

    /// Store every assigned chunk (looking its bytes up in `chunks`), simulating
    /// each provider delivering its whole assignment. Relies on `assign` having
    /// handed out only chunks a provider can serve.
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
                    held.can_serve(h),
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
    fn a_known_holder_is_preferred_over_an_unknown_provider() {
        // One chunk, cap 1, with the Unknown (speculative) provider listed *before*
        // the real holder. It must go to the known holder, not be wasted on the
        // Unknown — the regression this ordering guards against.
        let data: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100); // 1 chunk
        let only = chunks[0].0;
        let unknown = Holdings::unknown();
        let holder = subset(&chunks, &[0]);
        let mut plan = Plan::new(manifest);

        let assignment = plan.assign(&[&unknown, &holder], 1);
        assert!(
            assignment[0].is_empty(),
            "the unknown provider must not get it"
        );
        assert_eq!(assignment[1], vec![only], "the known holder must get it");
    }

    #[test]
    fn an_unknown_provider_is_used_as_a_last_resort() {
        // No one *reports* holding the chunk, so the only hope is to probe the
        // Unknown provider optimistically.
        let data: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100);
        let only = chunks[0].0;
        let unknown = Holdings::unknown();
        let mut plan = Plan::new(manifest);

        let assignment = plan.assign(&[&unknown], usize::MAX);
        assert_eq!(assignment[0], vec![only]);
    }

    #[test]
    fn streaming_window_gates_and_slides_with_the_frontier() {
        // 10 chunks, window 3: only chunks within `window` positions of the
        // frontier are eligible to fetch (in playback order); nothing further
        // ahead, so memory stays bounded. As the frontier advances, the window
        // slides.
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100); // 10 distinct chunks
        let seeder = full(&chunks);
        let mut plan = Plan::new(manifest);
        plan.set_selection(Selection::Streaming { window: 3 });

        // Frontier at 0 → assign offers only 0,1,2, in playback order.
        let a = plan.assign(&[&seeder], usize::MAX);
        assert_eq!(a[0], vec![chunks[0].0, chunks[1].0, chunks[2].0]);

        // Fetch + deliver them; the frontier advances to 3.
        for (h, d) in chunks.iter().take(3) {
            plan.store(*h, d.clone());
            plan.advance_delivery(true);
        }
        assert_eq!(plan.frontier(), 3);

        // The window has slid: now only 3,4,5 are eligible.
        let a = plan.assign(&[&seeder], usize::MAX);
        assert_eq!(a[0], vec![chunks[3].0, chunks[4].0, chunks[5].0]);
    }

    #[test]
    fn streaming_drops_each_chunk_after_its_last_delivery() {
        // Four distinct chunks: delivering each (with dropping on) frees exactly
        // one, so memory shrinks to zero — not the whole blob retained.
        let data: Vec<u8> = (0..400u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100); // 4 distinct chunks
        let mut plan = Plan::new(manifest);
        for (h, d) in &chunks {
            plan.store(*h, d.clone());
        }
        assert_eq!(plan.stored_count(), 4);

        for i in 0..4 {
            plan.advance_delivery(true);
            assert_eq!(plan.stored_count(), 4 - (i + 1));
        }
        assert!(plan.all_delivered());
        assert_eq!(plan.stored_count(), 0);
    }

    #[test]
    fn a_deduplicated_chunk_is_dropped_only_after_its_last_position() {
        // Three identical chunks: the manifest lists one hash at indices 0,1,2. It
        // must survive delivery of 0 and 1 and be freed only at 2.
        let data = vec![0x5au8; 300];
        let (manifest, chunks) = blob(&data, 100); // 1 distinct chunk, 3 positions
        let mut plan = Plan::new(manifest);
        plan.store(chunks[0].0, chunks[0].1.clone());
        assert_eq!(plan.stored_count(), 1);

        plan.advance_delivery(true); // index 0 — not the last position, kept
        assert_eq!(plan.stored_count(), 1);
        plan.advance_delivery(true); // index 1 — still not last, kept
        assert_eq!(plan.stored_count(), 1);
        plan.advance_delivery(true); // index 2 — last position, dropped
        assert_eq!(plan.stored_count(), 0);
        assert!(plan.all_delivered());
    }

    #[test]
    fn a_refused_chunk_is_not_offered_to_that_provider_again() {
        // The livelock guard for work-stealing: once a provider refuses a chunk
        // (answered Absent), assign must never offer it that chunk again.
        let data: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let (manifest, chunks) = blob(&data, 100); // 2 chunks
        let (c0, c1) = (chunks[0].0, chunks[1].0);

        // A known holder of both and an unknown provider — both refuse chunk 0.
        let mut known = full(&chunks);
        known.refuse(&c0);
        let mut unknown = Holdings::unknown();
        unknown.refuse(&c0);
        let mut plan = Plan::new(manifest);

        let assignment = plan.assign(&[&known, &unknown], usize::MAX);
        // No one is offered chunk 0, so it stays pending...
        assert!(plan.pending_contains(c0));
        for a in &assignment {
            assert!(!a.contains(&c0), "a refused chunk must not be re-offered");
        }
        // ...while chunk 1 (refused by no one) goes to the known holder.
        assert_eq!(assignment[0], vec![c1]);
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
        fn stored_count(&self) -> usize {
            self.have.len()
        }

        fn pending_contains(&self, hash: Hash) -> bool {
            self.pending.contains(&hash)
        }
    }
}
