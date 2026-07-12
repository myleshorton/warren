//! Warren — roster: authenticated channel membership.
//!
//! A channel's PSK gates *discovery + reading* (see [`crate::channel`]); the **roster**
//! gates *membership + authorship*. Membership is data: `member.add` / `member.remove`
//! records in members' own signed feeds, carrying the same merge clock as any other
//! record ([`crate::merge`]), folded — in the merge-linearized (causal) order — from a
//! **founder** genesis into the current member set.
//!
//! The fold is pure and deterministic, so every node holding the same records computes the
//! same membership: the convergence invariant of [`crate::merge`], extended to *who is in
//! the room*. This is the write/identity defense against a censor who merely holds the PSK
//! — possession of the secret no longer makes you a member; an existing member has to
//! vouch you in, and that vouch is itself an auditable, ordered record.
//!
//! Design + threat model: `docs/roster-membership.md`. This module is v1's substrate (the
//! pure fold); founder genesis, the invite-carried authorization, and the authorship gate
//! on aggregated feeds are app-side wiring built on top.

use std::collections::BTreeSet;

use crate::merge::{self, Entry, WriterId};

/// `content_type` of the two membership records (the record's `meta.subject` is the hex
/// feed key being added/removed; its author is the signer).
pub const ADD: &str = "member.add";
pub const REMOVE: &str = "member.remove";

/// One membership change: `author` (the signing feed key) adds or removes `subject`.
/// Decoded from a `member.add`/`member.remove` record; the merge metadata that *orders*
/// it lives on the enclosing [`Entry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub author: WriterId,
    pub subject: WriterId,
    pub add: bool,
}

/// Fold `changes` — **already in causal (merge-linearized) order** — from a `founder`
/// genesis into the current member set.
///
/// Authorization is evaluated as we go, so it is a function of the ordered prefix alone:
/// - the `founder` is a member from the start (the implicit genesis entry);
/// - a change is honored only if its `author` is a member *at that point*; a change signed
///   by a not-yet-authorized key is **inert** (dropped) — this is what stops a censor who
///   only holds the PSK from writing themselves into the room;
/// - `add` inserts `subject`, `remove` deletes it;
/// - the `founder` cannot be removed (genesis is permanent) — a v1 simplification that
///   avoids a room bricking itself; succession/handover is future work.
///
/// Deterministic ⇒ convergent: identical ordered input ⇒ identical set. Concurrent changes
/// are put in one order by [`merge`] first (see [`resolve`]); within that order this is
/// *last-authorized-op-per-subject wins*. True **remove-wins** on genuine concurrency
/// (erring toward exclusion when an add and a remove are causally incomparable) needs the
/// concurrency relation and is a tracked v1 refinement — see the design note.
pub fn members(founder: WriterId, changes: &[Change]) -> BTreeSet<WriterId> {
    let mut set = BTreeSet::new();
    set.insert(founder);
    for c in changes {
        // Author must be a member as of here; the founder is never removed/re-added.
        if !set.contains(&c.author) || c.subject == founder {
            continue;
        }
        if c.add {
            set.insert(c.subject);
        } else {
            set.remove(&c.subject);
        }
    }
    set
}

/// Linearize roster `entries` (via [`merge::linearize`]) and fold them into the member
/// set — the network-facing entry point. Hand it every [`Change`] you've decoded (each
/// wrapped in its record's merge [`Entry`]); it computes membership in the one causal order
/// all participants agree on. Entries whose causal ancestor hasn't arrived stay *pending*
/// in `merge` and are simply not yet applied (you can't authorize on an unseen prefix),
/// so membership grows monotonically as feeds fill in — never reordering what it has.
pub fn resolve(founder: WriterId, entries: Vec<Entry<Change>>) -> BTreeSet<WriterId> {
    let ordered = merge::linearize(entries).ordered;
    let changes: Vec<Change> = ordered.into_iter().map(|e| e.payload).collect();
    members(founder, &changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> WriterId {
        [n; 32]
    }

    fn add(author: u8, subject: u8) -> Change {
        Change { author: id(author), subject: id(subject), add: true }
    }
    fn remove(author: u8, subject: u8) -> Change {
        Change { author: id(author), subject: id(subject), add: false }
    }

    #[test]
    fn founder_is_a_member_with_no_changes() {
        assert_eq!(members(id(1), &[]), BTreeSet::from([id(1)]));
    }

    #[test]
    fn founder_adds_a_member() {
        assert_eq!(members(id(1), &[add(1, 2)]), BTreeSet::from([id(1), id(2)]));
    }

    #[test]
    fn vouching_is_transitive() {
        // founder(1) adds 2; then 2 — now authorized — adds 3.
        let set = members(id(1), &[add(1, 2), add(2, 3)]);
        assert_eq!(set, BTreeSet::from([id(1), id(2), id(3)]));
    }

    #[test]
    fn a_change_by_a_non_member_is_inert() {
        // 9 is not a member, so its add of 8 (and of itself) does nothing.
        let set = members(id(1), &[add(9, 8), add(9, 9)]);
        assert_eq!(set, BTreeSet::from([id(1)]));
    }

    #[test]
    fn add_then_remove_removes() {
        let set = members(id(1), &[add(1, 2), remove(1, 2)]);
        assert_eq!(set, BTreeSet::from([id(1)]));
    }

    #[test]
    fn a_removed_member_cannot_authorize_afterwards() {
        // 1 adds 2, then removes 2; 2's later add of 3 is inert (2 is out by then).
        let set = members(id(1), &[add(1, 2), remove(1, 2), add(2, 3)]);
        assert_eq!(set, BTreeSet::from([id(1)]));
    }

    #[test]
    fn founder_is_not_removable() {
        let set = members(id(1), &[add(1, 2), remove(2, 1)]);
        assert_eq!(set, BTreeSet::from([id(1), id(2)]));
    }

    // --- resolve(): ordering is merge's job; membership converges regardless of arrival ---

    /// A roster record as a merge entry: `writer` authored it at `index`, having seen the
    /// positions in `clock`; `lamport` is supplied for the tiebreak.
    fn entry(writer: u8, index: u64, lamport: u64, clock: &[(u8, u64)], c: Change) -> Entry<Change> {
        Entry {
            writer: id(writer),
            index,
            lamport,
            clock: clock.iter().map(|&(w, k)| (id(w), k)).collect(),
            payload: c,
        }
    }

    #[test]
    fn resolve_folds_in_causal_order_independent_of_input_order() {
        // founder(1) adds 2 (1's feed #0); 2, having seen it, adds 3 (2's feed #0, clock
        // {1:1} — saw 1's first record). The add(2,3) causally follows add(1,2).
        let e_add2 = entry(1, 0, 0, &[], add(1, 2));
        let e_add3 = entry(2, 0, 1, &[(1, 1)], add(2, 3));

        let forward = resolve(id(1), vec![e_add2.clone(), e_add3.clone()]);
        let shuffled = resolve(id(1), vec![e_add3, e_add2]);
        assert_eq!(forward, BTreeSet::from([id(1), id(2), id(3)]));
        assert_eq!(forward, shuffled, "membership converges regardless of arrival order");
    }

    #[test]
    fn resolve_drops_a_change_whose_authorizing_prefix_is_missing() {
        // add(2,3) depends on 1's record #0 (add of 2), which we don't provide → it's
        // pending in merge, so 2 was never authorized and 3 isn't added.
        let e_add3 = entry(2, 0, 1, &[(1, 1)], add(2, 3));
        assert_eq!(resolve(id(1), vec![e_add3]), BTreeSet::from([id(1)]));
    }
}
