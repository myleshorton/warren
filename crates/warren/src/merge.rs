//! Deterministic multi-writer causal merge (Layer 3): linearize records from many
//! signed per-writer feeds into one order that every participant computes identically.
//!
//! Live-tail (see [`live-tail.md`](../../docs/live-tail.md)) delivers *one author's*
//! log in order; a group chat is many authors at once. To render a conversation the
//! same way for everyone, each record carries a **version-vector clock** of what its
//! author had seen when writing it, plus a **Lamport timestamp**; a pure linearizer
//! topologically sorts the resulting causal DAG, breaking concurrency with a
//! deterministic `(lamport, writer, index)` tiebreak.
//!
//! Two properties make this the convergence layer under a shared room:
//! - **Convergence:** any node holding the *same set of records* produces the *same*
//!   ordered sequence, regardless of arrival order — the DAG and tiebreak are
//!   functions of the records alone.
//! - **Grow-only prefix:** a record whose causal ancestor hasn't arrived yet is held
//!   `pending` (you can't place a reply before the message it answers); it becomes
//!   orderable once the ancestor arrives, and what's already ordered never reorders.
//!
//! This is sans-IO and pure — the same discipline as [`sync`](sync). The network
//! layer (Layer 2) already carries the records; ordering them is entirely local.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

/// A writer's identity in a room: its feed public-key bytes.
pub type WriterId = [u8; 32];

/// A position in a writer's feed: `(writer, index)`, 0-based.
type Pos = (WriterId, u64);

/// A version vector: `clock[w] = k` means "causally follows the first `k` records of
/// writer `w`" (that writer's records at indices `0..k`). A [`BTreeMap`] so iteration
/// — and thus every derived value — is deterministic.
pub type Clock = BTreeMap<WriterId, u64>;

/// One record positioned in the causal DAG. `payload` is opaque to the merge layer
/// (the app's decoded record, or an index into its own store); merging needs only the
/// causal metadata. Cheap to construct; `T` is cloned into the output.
#[derive(Debug, Clone)]
pub struct Entry<T> {
    /// The record's author (its feed key).
    pub writer: WriterId,
    /// Its 0-based position in the author's feed.
    pub index: u64,
    /// Logical timestamp: `1 + max(lamport)` over everything in `clock` (see
    /// [`next_lamport`]). The primary sort key, so messages land in roughly send order.
    pub lamport: u64,
    /// What the author had causally seen when appending — its cross-writer
    /// dependencies. The author's own prior records are implied by `index`.
    pub clock: Clock,
    /// The record itself (opaque here).
    pub payload: T,
}

/// The result of [`linearize`]: the agreed causal order, plus the records that can't
/// be placed yet because a causal ancestor is missing.
#[derive(Debug)]
pub struct Linearized<T> {
    /// Every placeable record, in the one total order all participants agree on.
    pub ordered: Vec<Entry<T>>,
    /// Records with a not-yet-received causal ancestor (and anything depending on
    /// them). They order once the missing ancestor arrives. Order here is unspecified.
    pub pending: Vec<Entry<T>>,
}

/// The Lamport timestamp a new record should carry, given the records its author has
/// observed: `1 + max(lamport)`, or `0` if it is the very first record anywhere.
pub fn next_lamport<T>(observed: &[Entry<T>]) -> u64 {
    observed
        .iter()
        .map(|e| e.lamport)
        .max()
        .map_or(0, |m| m + 1)
}

/// The cross-writer dependency positions of an entry (deduplicated). An entry depends
/// on the latest record it saw from each *other* writer — `(w, clock[w]-1)` — plus its
/// own immediately-preceding record `(writer, index-1)`. Its own `clock[writer]` is
/// ignored: same-writer ordering is the sequential edge, and treating a self entry as a
/// cross-dep could otherwise manufacture a self-loop.
fn deps_of<T>(e: &Entry<T>) -> BTreeSet<Pos> {
    let mut deps = BTreeSet::new();
    if e.index > 0 {
        deps.insert((e.writer, e.index - 1));
    }
    for (&w, &k) in &e.clock {
        if w != e.writer && k > 0 {
            deps.insert((w, k - 1));
        }
    }
    deps
}

/// Linearize a set of records into the one causal order every participant agrees on.
///
/// A deterministic topological sort (Kahn's algorithm): a record is emitted only once
/// all its causal dependencies have been emitted, and among those simultaneously ready
/// the least `(lamport, writer, index)` goes first. A record whose dependency set
/// references a position **not present** in `entries` (a missing ancestor) can never
/// reach in-degree zero, so it — and its descendants — fall out as `pending`.
///
/// Duplicate positions (the same `(writer, index)` twice) are ignored after the first.
pub fn linearize<T: Clone>(entries: Vec<Entry<T>>) -> Linearized<T> {
    // Index the entries by position, dropping duplicates (first wins).
    let mut by_pos: BTreeMap<Pos, Entry<T>> = BTreeMap::new();
    for e in entries {
        by_pos.entry((e.writer, e.index)).or_insert(e);
    }
    let present: BTreeSet<Pos> = by_pos.keys().copied().collect();

    // Build in-degrees (counting *every* dependency, present or missing, so a missing
    // ancestor keeps its descendants pending) and the reverse edges from present deps.
    let mut indegree: BTreeMap<Pos, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<Pos, Vec<Pos>> = BTreeMap::new();
    for (&pos, e) in &by_pos {
        let deps = deps_of(e);
        indegree.insert(pos, deps.len());
        for d in deps {
            if present.contains(&d) {
                dependents.entry(d).or_default().push(pos);
            }
            // A missing `d` contributes to indegree but is never decremented → `pos`
            // stays pending, which is correct: its ancestor hasn't arrived.
        }
    }

    // Kahn, popping the least (lamport, writer, index) among ready records. The heap
    // key carries the sort fields directly, so no lookup is needed to compare.
    let mut ready: BinaryHeap<Reverse<(u64, WriterId, u64)>> = BinaryHeap::new();
    for (&pos, &deg) in &indegree {
        if deg == 0 {
            let e = &by_pos[&pos];
            ready.push(Reverse((e.lamport, e.writer, e.index)));
        }
    }

    let mut ordered = Vec::with_capacity(by_pos.len());
    while let Some(Reverse((_, writer, index))) = ready.pop() {
        let pos = (writer, index);
        ordered.push(by_pos[&pos].clone());
        if let Some(children) = dependents.get(&pos) {
            for &child in children {
                let deg = indegree.get_mut(&child).expect("child indegree");
                *deg -= 1;
                if *deg == 0 {
                    let ce = &by_pos[&child];
                    ready.push(Reverse((ce.lamport, ce.writer, ce.index)));
                }
            }
        }
    }

    // Whatever never got emitted is pending (a missing ancestor blocked it).
    let emitted: BTreeSet<Pos> = ordered.iter().map(|e| (e.writer, e.index)).collect();
    let pending = by_pos
        .into_iter()
        .filter(|(pos, _)| !emitted.contains(pos))
        .map(|(_, e)| e)
        .collect();

    Linearized { ordered, pending }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(n: u8) -> WriterId {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    /// Build an entry; `clock` given as `(writer, seen_len)` pairs.
    fn entry(
        writer: WriterId,
        index: u64,
        lamport: u64,
        clock: &[(WriterId, u64)],
    ) -> Entry<String> {
        Entry {
            writer,
            index,
            lamport,
            clock: clock.iter().copied().collect(),
            payload: format!("{}:{index}", writer[0]),
        }
    }

    fn order_ids<T: Clone + ToString>(lin: &Linearized<T>) -> Vec<String> {
        lin.ordered.iter().map(|e| e.payload.to_string()).collect()
    }

    /// Rotations + reversal of a Vec — enough distinct arrival orders to prove the
    /// output doesn't depend on input order, without needing an RNG dependency.
    fn permutations<T: Clone>(v: &[T]) -> Vec<Vec<T>> {
        let mut out = vec![v.to_vec()];
        let mut rev = v.to_vec();
        rev.reverse();
        out.push(rev);
        for k in 1..v.len() {
            let mut rot = v.to_vec();
            rot.rotate_left(k);
            out.push(rot);
        }
        out
    }

    #[test]
    fn same_writer_stays_in_feed_order() {
        let a = w(1);
        let entries = vec![
            entry(a, 0, 0, &[]),
            entry(a, 1, 1, &[]),
            entry(a, 2, 2, &[]),
        ];
        let lin = linearize(entries);
        assert!(lin.pending.is_empty());
        assert_eq!(order_ids(&lin), vec!["1:0", "1:1", "1:2"]);
    }

    #[test]
    fn a_reply_never_precedes_the_message_it_answers() {
        // b's message saw a:0, so a:0 must come before b:0 regardless of tiebreak.
        let (a, b) = (w(1), w(2));
        let entries = vec![
            entry(a, 0, 0, &[]),
            entry(b, 0, 1, &[(a, 1)]), // b:0 depends on a:0
        ];
        for p in permutations(&entries) {
            let lin = linearize(p);
            assert!(lin.pending.is_empty());
            assert_eq!(
                order_ids(&lin),
                vec!["1:0", "2:0"],
                "a:0 must precede its reply b:0"
            );
        }
    }

    #[test]
    fn convergence_identical_order_across_arrival_orders() {
        // A small causal DAG across three writers with concurrency.
        let (a, b, c) = (w(1), w(2), w(3));
        let entries = vec![
            entry(a, 0, 0, &[]),
            entry(b, 0, 0, &[]),               // concurrent with a:0
            entry(a, 1, 1, &[(b, 1)]),         // a:1 saw b:0
            entry(c, 0, 2, &[(a, 2), (b, 1)]), // c:0 saw a:1 and b:0
            entry(b, 1, 3, &[(c, 1), (a, 2)]), // b:1 saw c:0 and a:1
        ];
        let expected = order_ids(&linearize(entries.clone()));
        // Determinism: every arrival order yields the identical sequence.
        for p in permutations(&entries) {
            assert_eq!(
                order_ids(&linearize(p)),
                expected,
                "order must not depend on arrival"
            );
        }
        // Sanity: it's a valid topological order (each dep precedes its dependent).
        let pos_at = |id: &str| expected.iter().position(|x| x == id).unwrap();
        assert!(pos_at("2:0") < pos_at("1:1")); // b:0 → a:1
        assert!(pos_at("1:1") < pos_at("3:0")); // a:1 → c:0
        assert!(pos_at("3:0") < pos_at("2:1")); // c:0 → b:1
    }

    #[test]
    fn concurrent_records_break_ties_by_lamport_then_writer() {
        // Two independent first messages: lower lamport first; equal lamport → lower
        // writer id first.
        let (a, b) = (w(1), w(2));
        let lin = linearize(vec![entry(b, 0, 0, &[]), entry(a, 0, 0, &[])]);
        assert_eq!(
            order_ids(&lin),
            vec!["1:0", "2:0"],
            "equal lamport → writer id breaks the tie"
        );

        let lin = linearize(vec![entry(a, 0, 5, &[]), entry(b, 0, 2, &[])]);
        assert_eq!(
            order_ids(&lin),
            vec!["2:0", "1:0"],
            "lower lamport wins over lower writer id"
        );
    }

    #[test]
    fn a_missing_ancestor_holds_its_descendants_pending() {
        // b:0 depends on a:0, but a:0 hasn't arrived — b:0 (and b:1 after it) pend.
        let (a, b) = (w(1), w(2));
        let entries = vec![
            entry(b, 0, 1, &[(a, 1)]), // needs a:0 (absent)
            entry(b, 1, 2, &[(a, 1)]),
        ];
        let lin = linearize(entries);
        assert!(
            lin.ordered.is_empty(),
            "nothing is placeable without the ancestor"
        );
        let mut pend: Vec<String> = lin.pending.iter().map(|e| e.payload.clone()).collect();
        pend.sort();
        assert_eq!(pend, vec!["2:0", "2:1"]);
    }

    #[test]
    fn the_prefix_grows_and_never_reorders_as_records_arrive() {
        let (a, b) = (w(1), w(2));
        let a0 = entry(a, 0, 0, &[]);
        let b0 = entry(b, 0, 1, &[(a, 1)]); // depends on a:0

        // Before a:0 arrives: b:0 is pending, nothing ordered.
        let before = linearize(vec![b0.clone()]);
        assert!(before.ordered.is_empty());
        assert_eq!(before.pending.len(), 1);

        // After a:0 arrives: the prefix grows to [a:0, b:0], and a:0 is still first.
        let after = linearize(vec![b0, a0]);
        assert!(after.pending.is_empty());
        assert_eq!(order_ids(&after), vec!["1:0", "2:0"]);
    }

    #[test]
    fn next_lamport_is_one_past_the_max_seen() {
        let a = w(1);
        assert_eq!(next_lamport::<String>(&[]), 0);
        let seen = vec![entry(a, 0, 3, &[]), entry(a, 1, 7, &[])];
        assert_eq!(next_lamport(&seen), 8);
    }

    #[test]
    fn duplicate_positions_are_folded() {
        let a = w(1);
        let lin = linearize(vec![entry(a, 0, 0, &[]), entry(a, 0, 0, &[])]);
        assert_eq!(lin.ordered.len(), 1, "the same (writer, index) counts once");
    }
}
