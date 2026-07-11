//! A room: accumulate records from many writers' feeds and present the one merged,
//! causally-ordered view (Layer 3c). It wraps the pure [`merge`] linearizer with the
//! two stateful bits a shared room needs:
//!
//! - the **observed frontier** — how much of each writer's feed we hold — so a new
//!   local message can be stamped with a clock that causally follows everything we've
//!   seen ([`Room::next_message_clock`]);
//! - **record accumulation**, so the view can be re-linearized as feeds live-update
//!   ([`Room::observe`] / [`Room::view`]).
//!
//! Still pure and sans-IO: the app feeds it decoded blocks from `subscribe` / discovery
//! and reads back the ordered transcript. Wiring it to the live network path (a chat
//! app's accept + publish loop) is the remaining glue on top.

use std::collections::{BTreeMap, BTreeSet};

use crate::merge::{self, Clock, Entry, Linearized, WriterId};
use crate::record::Record;

/// The merged state of one room: every observed record, keyed by its feed position.
#[derive(Default)]
pub struct Room {
    entries: BTreeMap<(WriterId, u64), Entry<Record>>,
}

impl Room {
    /// An empty room.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one decoded block at `index` in its author's feed. Returns `true` if it
    /// was new (a first sighting of that position). A record whose `author` isn't valid
    /// hex is ignored (returns `false`) — it can't be placed in the causal DAG.
    pub fn observe(&mut self, index: u64, record: Record) -> bool {
        match record.into_entry(index) {
            Some(e) => self.entries.insert((e.writer, e.index), e).is_none(),
            None => false,
        }
    }

    /// How many records we hold (across all writers).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the room has no records yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The merged, causally-ordered view of everything observed so far, plus any
    /// records still waiting on a missing ancestor (see [`merge::linearize`]).
    pub fn view(&self) -> Linearized<Record> {
        merge::linearize(self.entries.values().cloned().collect())
    }

    /// The observed frontier: for each writer, the length of the **contiguous** prefix
    /// of its feed we hold (`clock[w] = k` ⇔ records `0..k` are all present). A gap
    /// stops the count, since a clock must not claim records we can't causally rely on.
    pub fn frontier(&self) -> Clock {
        let writers: BTreeSet<WriterId> = self.entries.keys().map(|(w, _)| *w).collect();
        let mut f = Clock::new();
        for w in writers {
            let mut k = 0u64;
            while self.entries.contains_key(&(w, k)) {
                k += 1;
            }
            f.insert(w, k);
        }
        f
    }

    /// The `(clock, lamport)` a new local message should carry: the current frontier
    /// and `1 + max(lamport observed)`. Stamp these onto the record before publishing
    /// so it causally follows everything this node has seen.
    pub fn next_message_clock(&self) -> (Clock, u64) {
        let lamport = self
            .entries
            .values()
            .map(|e| e.lamport)
            .max()
            .map_or(0, |m| m + 1);
        (self.frontier(), lamport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util;

    fn w(n: u8) -> WriterId {
        let mut b = [0u8; 32];
        b[0] = n;
        b
    }

    /// A record authored by `writer`, carrying the given `clock` (as writer→len) and
    /// `lamport`, with `body` as its payload marker.
    fn msg(writer: WriterId, clock: &[(WriterId, u64)], lamport: u64, body: &str) -> Record {
        Record {
            author: util::to_hex(&writer),
            created_at: 0,
            content_type: "text/plain".into(),
            body: Some(body.into()),
            clock: clock.iter().map(|(k, v)| (util::to_hex(k), *v)).collect(),
            lamport,
            ..Default::default()
        }
    }

    fn bodies(lin: &Linearized<Record>) -> Vec<String> {
        lin.ordered
            .iter()
            .map(|e| e.payload.body.clone().unwrap_or_default())
            .collect()
    }

    #[test]
    fn merges_two_writers_into_one_causal_order() {
        let (a, b) = (w(1), w(2));
        let mut room = Room::new();
        // a:0 "hi"; b sees it, replies b:0 "hey" (clock {a:1}, lamport 1).
        room.observe(0, msg(a, &[], 0, "hi"));
        room.observe(0, msg(b, &[(a, 1)], 1, "hey"));
        let v = room.view();
        assert!(v.pending.is_empty());
        assert_eq!(bodies(&v), vec!["hi", "hey"]);
    }

    #[test]
    fn frontier_counts_only_the_contiguous_prefix() {
        let a = w(1);
        let mut room = Room::new();
        room.observe(0, msg(a, &[], 0, "a0"));
        room.observe(2, msg(a, &[], 2, "a2")); // gap at index 1
        let f = room.frontier();
        assert_eq!(
            f.get(&a),
            Some(&1),
            "the gap at index 1 caps the frontier at 1"
        );
    }

    #[test]
    fn a_message_stamped_from_the_frontier_sorts_after_everything_seen() {
        let (a, b) = (w(1), w(2));
        let mut room = Room::new();
        room.observe(0, msg(a, &[], 0, "a0"));
        room.observe(1, msg(a, &[], 1, "a1"));
        room.observe(0, msg(b, &[(a, 1)], 1, "b0"));

        // This node (writer c) publishes with a clock derived from what it has seen.
        let c = w(3);
        let (clock, lamport) = room.next_message_clock();
        assert_eq!(clock.get(&a), Some(&2));
        assert_eq!(clock.get(&b), Some(&1));
        let clock_pairs: Vec<(WriterId, u64)> = clock.into_iter().collect();
        room.observe(0, msg(c, &clock_pairs, lamport, "c0"));

        let v = room.view();
        assert!(v.pending.is_empty());
        assert_eq!(
            *bodies(&v).last().unwrap(),
            "c0",
            "a message follows all it observed"
        );
    }

    #[test]
    fn a_reply_to_an_unseen_message_waits_until_it_arrives() {
        let (a, b) = (w(1), w(2));
        let mut room = Room::new();
        // b replies to a:0 before we've received a:0.
        room.observe(0, msg(b, &[(a, 1)], 1, "reply"));
        let v = room.view();
        assert!(v.ordered.is_empty());
        assert_eq!(v.pending.len(), 1);

        // a:0 arrives → the reply slots in behind it.
        room.observe(0, msg(a, &[], 0, "cause"));
        let v = room.view();
        assert!(v.pending.is_empty());
        assert_eq!(bodies(&v), vec!["cause", "reply"]);
    }

    #[test]
    fn re_observing_a_position_is_idempotent() {
        let a = w(1);
        let mut room = Room::new();
        assert!(room.observe(0, msg(a, &[], 0, "x")));
        assert!(
            !room.observe(0, msg(a, &[], 0, "x")),
            "same position is not new"
        );
        assert_eq!(room.len(), 1);
    }
}
