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
use crate::record::Record;
use crate::util;

/// The `meta` key a membership record carries: the hex feed key being added/removed.
pub const SUBJECT: &str = "subject";

/// `content_type` of the two membership records (the record's `meta.subject` is the hex
/// feed key being added/removed).
pub const ADD: &str = "member.add";
pub const REMOVE: &str = "member.remove";

/// One membership change, decoded from a record's payload: add or remove `subject`.
///
/// The **author is deliberately not carried here** — it is the record's authenticated feed
/// key ([`Entry::writer`], which the feed layer verifies per block). Authorization is
/// evaluated against that authenticated author (see [`resolve`]); a self-declared author in
/// the payload would be forgeable and must never be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub subject: WriterId,
    pub add: bool,
}

/// Fold changes — **already in causal (merge-linearized) order**, each paired with its
/// **authenticated author** — from a `founder` genesis into the current member set.
///
/// Authorization is evaluated as we go, so it is a function of the ordered prefix alone:
/// - the `founder` is a member from the start (the implicit genesis entry);
/// - a change is honored only if its author is a member *at that point*; a change by a
///   not-yet-authorized key is **inert** — this is what stops a censor who only holds the
///   PSK from writing themselves into the room;
/// - `add` inserts `subject`, `remove` deletes it;
/// - the `founder` cannot be removed (genesis is permanent) — a v1 simplification that
///   avoids a room bricking itself; succession/handover is future work.
///
/// Deterministic ⇒ convergent: identical ordered input ⇒ identical set. Concurrent changes
/// are put in one order by [`merge`] first (see [`resolve`]); within that order this is
/// *last-authorized-op-per-subject wins*. True **remove-wins** on genuine concurrency
/// (erring toward exclusion when an add and a remove are causally incomparable) needs the
/// concurrency relation and is a tracked v1 refinement — see the design note.
pub fn members(founder: WriterId, changes: &[(WriterId, Change)]) -> BTreeSet<WriterId> {
    let mut set = BTreeSet::new();
    set.insert(founder);
    for (author, c) in changes {
        // Author must be a member as of here; the founder is never removed/re-added.
        if !set.contains(author) || c.subject == founder {
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
/// all participants agree on.
///
/// The author of each change is taken from [`Entry::writer`] — the record's authenticated
/// feed key, verified per block by the feed layer — never from the payload, so a forged
/// self-declared author can't bypass authorization. Entries whose causal ancestor hasn't
/// arrived stay *pending* in `merge` and aren't applied yet (you can't authorize on an
/// unseen prefix). What grows monotonically as feeds fill in is `merge`'s **ordered record
/// sequence** (its grow-only prefix, never reordered); the member *set* is a deterministic
/// fold over that sequence and may grow *or* shrink — a newly-orderable `member.remove`
/// reduces it. What never happens is a reorder that retroactively changes an earlier
/// membership decision.
pub fn resolve(founder: WriterId, entries: Vec<Entry<Change>>) -> BTreeSet<WriterId> {
    let ordered = merge::linearize(entries).ordered;
    let changes: Vec<(WriterId, Change)> =
        ordered.into_iter().map(|e| (e.writer, e.payload)).collect();
    members(founder, &changes)
}

/// Decode a membership [`Change`] from a record, or `None` if it isn't a `member.add` /
/// `member.remove` (or its `meta.subject` isn't a 32-byte hex key). The author is *not*
/// read from the record here — [`members_from_records`] takes it from the authenticated
/// feed position, never a payload field.
pub fn change_from_record(rec: &Record) -> Option<Change> {
    let add = match rec.content_type.as_str() {
        ADD => true,
        REMOVE => false,
        _ => return None,
    };
    let subject = rec
        .meta
        .get(SUBJECT)
        .and_then(|v| v.as_str())
        .and_then(util::bytes_from_hex::<32>)?;
    Some(Change { subject, add })
}

/// The `meta` map a `member.add`/`member.remove` record carries — the counterpart to
/// [`change_from_record`], for the publish side. Publish a roster record as a body-less
/// record with `content_type` [`ADD`]/[`REMOVE`] and this `meta`.
pub fn meta(subject: WriterId) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert(SUBJECT.to_string(), util::to_hex(&subject).into());
    m
}

/// Compute the current member set from a batch of feed records — typically every record an
/// aggregator discovered across the channel's members (many authors), which is exactly what
/// a session hands over.
///
/// Each item is `(writer, record)`, where `writer` is the **authenticated feed key** the
/// record's blocks were verified against (the feed it was replicated in) — the record's own
/// `author` field is self-declared and is **never** consulted here, so a forged `author`
/// can't bypass authorization. The batch may mix authors freely; the only ordering
/// requirement is that records **from the same author appear in that author's feed order**
/// (so the per-author roster index below is assigned correctly).
///
/// The roster is **its own append-only log**: only `member.add`/`member.remove` records
/// count, and each is positioned by its index *among that author's roster records* (a
/// roster-only index space, enumerated here), matching how a publisher stamps a membership
/// record's clock over other roster records only. So the roster orders and converges
/// independently of how much other content (videos, comments, chat) a feed carries — a
/// membership record never waits on a video to become orderable. Non-roster records are
/// ignored; the roster changes are folded via [`resolve`].
pub fn members_from_records(
    founder: WriterId,
    records: impl IntoIterator<Item = (WriterId, Record)>,
) -> BTreeSet<WriterId> {
    let mut next: std::collections::BTreeMap<WriterId, u64> = std::collections::BTreeMap::new();
    let entries: Vec<Entry<Change>> = records
        .into_iter()
        .filter_map(|(writer, rec)| {
            let change = change_from_record(&rec)?; // only roster records advance the index
            let index = *next.get(&writer).unwrap_or(&0);
            next.insert(writer, index + 1);
            Some(Entry {
                writer, // the authenticated feed key, not rec.author
                index,
                lamport: rec.lamport,
                clock: rec.causal_clock(),
                payload: change,
            })
        })
        .collect();
    resolve(founder, entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> WriterId {
        [n; 32]
    }

    /// (authenticated author, change) — the shape `members` folds.
    fn add(author: u8, subject: u8) -> (WriterId, Change) {
        (
            id(author),
            Change {
                subject: id(subject),
                add: true,
            },
        )
    }
    fn remove(author: u8, subject: u8) -> (WriterId, Change) {
        (
            id(author),
            Change {
                subject: id(subject),
                add: false,
            },
        )
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

    // --- resolve(): author is the authenticated Entry::writer; ordering is merge's job ---

    /// A roster record as a merge entry: feed key `writer` authored it at `index`, having
    /// seen the positions in `clock`; `lamport` supplied for the tiebreak. The payload is
    /// the change (subject + add) — the author is `writer`, not anything in the payload.
    fn entry(
        writer: u8,
        index: u64,
        lamport: u64,
        clock: &[(u8, u64)],
        subject: u8,
        add: bool,
    ) -> Entry<Change> {
        Entry {
            writer: id(writer),
            index,
            lamport,
            clock: clock.iter().map(|&(w, k)| (id(w), k)).collect(),
            payload: Change {
                subject: id(subject),
                add,
            },
        }
    }

    #[test]
    fn resolve_takes_the_author_from_the_authenticated_writer() {
        // The entry is authored by feed key 1 (writer) adding 2. Authorization uses the
        // writer, so 2 joins. (A forged payload author couldn't matter — there isn't one.)
        let e = entry(1, 0, 0, &[], 2, true);
        assert_eq!(resolve(id(1), vec![e]), BTreeSet::from([id(1), id(2)]));
    }

    #[test]
    fn resolve_folds_in_causal_order_independent_of_input_order() {
        // founder(1) adds 2 (1's feed #0); 2, having seen it, adds 3 (2's feed #0, clock
        // {1:1}). add(2->3) causally follows add(1->2).
        let e_add2 = entry(1, 0, 0, &[], 2, true);
        let e_add3 = entry(2, 0, 1, &[(1, 1)], 3, true);

        let forward = resolve(id(1), vec![e_add2.clone(), e_add3.clone()]);
        let shuffled = resolve(id(1), vec![e_add3, e_add2]);
        assert_eq!(forward, BTreeSet::from([id(1), id(2), id(3)]));
        assert_eq!(
            forward, shuffled,
            "membership converges regardless of arrival order"
        );
    }

    #[test]
    fn resolve_holds_a_change_pending_until_its_authorizing_prefix_arrives() {
        // add(2->3) depends on 1's record #0 (the add of 2), which we don't provide → it
        // stays pending in merge, so 2 was never authorized here and 3 isn't added. (It
        // would apply once 1's record arrives — nothing is discarded.)
        let e_add3 = entry(2, 0, 1, &[(1, 1)], 3, true);
        assert_eq!(resolve(id(1), vec![e_add3]), BTreeSet::from([id(1)]));
    }

    // --- the record bridge: decode real Records and fold a discovered batch ---

    /// A membership record: authored by feed key `author`, `content_type` add/remove of
    /// `subject`, with the given merge clock/lamport.
    fn rec(
        author: u8,
        content_type: &str,
        subject: u8,
        clock: &[(u8, u64)],
        lamport: u64,
    ) -> Record {
        Record {
            author: util::to_hex(&id(author)),
            content_type: content_type.to_string(),
            meta: meta(id(subject)),
            clock: clock
                .iter()
                .map(|&(w, k)| (util::to_hex(&id(w)), k))
                .collect(),
            lamport,
            ..Record::default()
        }
    }

    #[test]
    fn change_from_record_decodes_add_and_remove_and_ignores_others() {
        assert_eq!(
            change_from_record(&rec(1, ADD, 2, &[], 0)),
            Some(Change {
                subject: id(2),
                add: true
            })
        );
        assert_eq!(
            change_from_record(&rec(1, REMOVE, 2, &[], 0)),
            Some(Change {
                subject: id(2),
                add: false
            })
        );
        // a non-membership record (e.g. a video post) is not a change
        let mut video = rec(1, "video/mp4", 0, &[], 0);
        video.meta.clear();
        assert_eq!(change_from_record(&video), None);
    }

    #[test]
    fn members_from_records_folds_a_discovered_batch() {
        // (authenticated writer, record), each author's records in feed order. founder(1)
        // adds 2 (1's roster record #0); 2, having seen it, adds 3 (2's roster record #0,
        // clock {1:1} = saw 1's first roster record).
        let batch = vec![
            (id(1), rec(1, ADD, 2, &[], 0)),
            (id(2), rec(2, ADD, 3, &[(1, 1)], 1)),
        ];
        assert_eq!(
            members_from_records(id(1), batch),
            BTreeSet::from([id(1), id(2), id(3)])
        );
    }

    #[test]
    fn members_from_records_ignores_non_membership_records_without_shifting_the_index() {
        // The interleaved video is not a roster record, so it's ignored and does NOT
        // advance 1's roster-record index — 1's add-of-2 is still roster record #0.
        let batch = vec![
            (id(1), rec(1, "video/mp4", 0, &[], 0)),
            (id(1), rec(1, ADD, 2, &[], 0)),
        ];
        assert_eq!(
            members_from_records(id(1), batch),
            BTreeSet::from([id(1), id(2)])
        );
    }

    #[test]
    fn members_from_records_ignores_a_forged_author_field() {
        // An attacker (feed key 9) publishes an add-of-8, but forges the record's `author`
        // field to claim the founder (1). The authenticated writer is 9 (the feed it was
        // verified in) — which isn't a member — so the change is inert and 8 never joins.
        let mut forged = rec(9, ADD, 8, &[], 0);
        forged.author = util::to_hex(&id(1)); // lie: claim to be the founder
        assert_eq!(
            members_from_records(id(1), vec![(id(9), forged)]),
            BTreeSet::from([id(1)])
        );
    }
}
