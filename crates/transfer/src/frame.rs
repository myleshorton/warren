//! Application-level fragmentation over the datagram [`driver::Channel`].
//!
//! A `Channel` carries datagrams, each bounded by [`MAX_DATAGRAM`](crate::MAX_DATAGRAM);
//! a single [`sync::Message`](sync) — a blob chunk, a feed block with its proof,
//! or a manifest — can be larger than that. This module is the seam that lets a
//! message span several datagrams: [`fragment`] splits an encoded message into
//! datagram-sized pieces, each tagged with a message id and its index, and a
//! [`Reassembler`] collects the pieces of one message back into the original
//! bytes.
//!
//! It is **sans-IO**: pure over `&[u8]`, no sockets and no clock, so the
//! reassembly logic — including its behaviour under loss, reordering,
//! duplication, and hostile headers — is exercised by deterministic unit tests.
//! The crate's `Wire` pumps the fragments over a real channel.
//!
//! Reliability is left to the layer above: the transfer loop is stop-and-wait
//! and retransmits a whole message on timeout, so this module does **not** ack
//! or repair individual lost fragments. A message id lets the reassembler follow
//! the newest attempt and discard stragglers from an abandoned one, so a
//! retransmit never mixes with the message it replaces.

use std::collections::HashMap;

use wire::{Decoder, Encoder};

/// Upper bound on a reassembled message. A single sync message (chunk, block, or
/// manifest) must fit within this; it also caps the memory a peer can make us
/// buffer while reassembling. Generous for real messages — a manifest this large
/// addresses a ~32 GB blob — finite against abuse.
pub const MAX_MESSAGE: usize = 16 << 20;

/// Cap on the number of fragments in one message. Bounds the bookkeeping a single
/// (possibly forged) fragment header can force us to track, independently of the
/// [`MAX_MESSAGE`] byte cap (which a flood of tiny fragments wouldn't trip).
pub const MAX_FRAGMENTS: u64 = 1 << 16;

/// Bytes reserved in each datagram for the fragment header: three [`u64`]
/// varints (message id, fragment index, fragment count), each at most 10 bytes.
/// A conservative upper bound, so a fragment's header-plus-payload never exceeds
/// the datagram size it was split for.
const HEADER_BUDGET: usize = 32;

/// Split `payload` into fragments that each fit in a `datagram`-byte packet,
/// tagged with `msg_id` so a [`Reassembler`] can group and order them. Always
/// returns at least one fragment (an empty payload yields a single empty one).
///
/// `datagram` must exceed `HEADER_BUDGET` — otherwise the header alone would
/// fill (or overflow) a fragment and the "fits in `datagram` bytes" guarantee
/// couldn't hold. Callers pass the crate's `FRAGMENT`, which is far larger; the
/// assertion documents the precondition for any future caller.
pub fn fragment(msg_id: u64, payload: &[u8], datagram: usize) -> Vec<Vec<u8>> {
    debug_assert!(
        datagram > HEADER_BUDGET,
        "datagram ({datagram}) must exceed the fragment header budget ({HEADER_BUDGET})"
    );
    let budget = datagram.saturating_sub(HEADER_BUDGET).max(1);
    let count = payload.len().div_ceil(budget).max(1);
    (0..count)
        .map(|i| {
            let start = i * budget;
            let end = ((i + 1) * budget).min(payload.len());
            let mut enc = Encoder::new();
            enc.uint(msg_id);
            enc.uint(i as u64);
            enc.uint(count as u64);
            enc.raw(&payload[start..end]);
            enc.into_vec()
        })
        .collect()
}

/// Collects the fragments of a single message. Because the transfer loop is
/// stop-and-wait, only one message is ever in flight per direction, so this
/// tracks one message at a time and follows the newest id it sees.
#[derive(Default)]
pub struct Reassembler {
    current: Option<Partial>,
    /// Highest message id the caller has *accepted* (via [`Reassembler::accept`],
    /// after it validated the payload). Fragments at or below it are stragglers
    /// of a message already delivered and committed — dropped so a late one can't
    /// be reassembled and handed up again. Advanced only on accept, never on mere
    /// reassembly: a datagram with a bogus (huge, corrupted) id can complete on
    /// its own but is dropped by the caller's decode, so it must not be able to
    /// poison this watermark and wedge every later legitimate message.
    accepted: Option<u64>,
}

/// A message being reassembled: the fragments seen so far, keyed by index.
struct Partial {
    id: u64,
    count: usize,
    frags: HashMap<usize, Vec<u8>>,
    bytes: usize,
}

impl Reassembler {
    /// A reassembler with nothing in progress.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one received datagram. Returns `Some((id, payload))` when it
    /// completes a message — the caller decodes `payload` and, on success, calls
    /// [`Reassembler::accept`] with `id` to commit it. Returns `None` while more
    /// fragments are needed. Anything unparseable, abusive (a count or size past
    /// the caps), or stale (at or below the accepted watermark) is dropped — the
    /// transport treats such datagrams as noise, never as a failure.
    pub fn push(&mut self, datagram: &[u8]) -> Option<(u64, Vec<u8>)> {
        let mut dec = Decoder::new(datagram);
        let id = dec.uint().ok()?;
        let index = dec.uint().ok()?;
        let count = dec.uint().ok()?;
        let remaining = dec.remaining();
        let payload = dec.raw(remaining).ok()?;

        // Reject abusive framing before allocating anything for it.
        if count == 0 || count > MAX_FRAGMENTS || index >= count {
            return None;
        }
        let count = count as usize;
        let index = index as usize;

        // Drop stragglers from a message the caller has already accepted.
        if let Some(done) = self.accepted {
            if id <= done {
                return None;
            }
        }

        // Latch onto the newest message: keep accumulating the current one, start
        // fresh on a newer id, and ignore anything from an older (superseded) one.
        let restart = match &self.current {
            Some(p) if p.id == id => {
                if p.count != count {
                    return None; // inconsistent count for the same id: ignore
                }
                false
            }
            Some(p) if id < p.id => return None, // straggler from an old message
            _ => true,                           // nothing in progress, or a newer id
        };
        if restart {
            self.current = Some(Partial {
                id,
                count,
                frags: HashMap::new(),
                bytes: 0,
            });
        }

        let partial = self.current.as_mut().expect("just set");
        if !partial.frags.contains_key(&index) {
            if partial.bytes + payload.len() > MAX_MESSAGE {
                return None; // would exceed the reassembly cap: refuse to buffer
            }
            partial.bytes += payload.len();
            partial.frags.insert(index, payload.to_vec());
        }

        // Complete once every index in [0, count) is present. `frags` holds
        // `count` distinct in-range indices exactly when the message is whole.
        // The watermark is *not* advanced here — only when the caller accepts
        // the decoded payload — so a bogus id can't wedge later messages.
        if partial.frags.len() == partial.count {
            let mut out = Vec::with_capacity(partial.bytes);
            for i in 0..partial.count {
                out.extend_from_slice(&partial.frags[&i]);
            }
            let id = partial.id;
            self.current = None;
            return Some((id, out));
        }
        None
    }

    /// Commit `id` once the caller has validated the message [`Reassembler::push`]
    /// returned for it. Advances the watermark so stragglers and duplicates of
    /// that message are dropped from here on. Called only after a successful
    /// decode, so an undecodable (corrupt or hostile) reassembly leaves the
    /// watermark untouched.
    pub fn accept(&mut self, id: u64) {
        self.accepted = Some(self.accepted.map_or(id, |cur| cur.max(id)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DGRAM: usize = 1024;

    /// Push `frags` (in the given order) through a fresh reassembler, accepting
    /// each completed message (as the Wire does after a successful decode) and
    /// returning the last one completed.
    fn reassemble(frags: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut r = Reassembler::new();
        let mut done = None;
        for f in frags {
            if let Some((id, msg)) = r.push(f) {
                r.accept(id);
                done = Some(msg);
            }
        }
        done
    }

    #[test]
    fn a_small_message_is_one_fragment_and_roundtrips() {
        let payload = b"just the head, please".to_vec();
        let frags = fragment(1, &payload, DGRAM);
        assert_eq!(frags.len(), 1);
        assert_eq!(reassemble(&frags), Some(payload));
    }

    #[test]
    fn an_empty_payload_roundtrips_as_one_empty_fragment() {
        let frags = fragment(7, &[], DGRAM);
        assert_eq!(frags.len(), 1);
        assert_eq!(reassemble(&frags), Some(Vec::new()));
    }

    #[test]
    fn a_large_message_spans_many_fragments_and_roundtrips() {
        let payload: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        let frags = fragment(2, &payload, DGRAM);
        assert!(frags.len() > 40, "should need many fragments");
        assert!(
            frags.iter().all(|f| f.len() <= DGRAM),
            "every fragment fits a datagram"
        );
        assert_eq!(reassemble(&frags), Some(payload));
    }

    #[test]
    fn fragments_reassemble_out_of_order() {
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
        let mut frags = fragment(3, &payload, DGRAM);
        frags.reverse();
        assert_eq!(reassemble(&frags), Some(payload));
    }

    #[test]
    fn duplicate_fragments_are_harmless() {
        let payload: Vec<u8> = (0..5_000u32).map(|i| i as u8).collect();
        let frags = fragment(4, &payload, DGRAM);
        // Feed every fragment twice, interleaved.
        let mut doubled = Vec::new();
        for f in &frags {
            doubled.push(f.clone());
            doubled.push(f.clone());
        }
        assert_eq!(reassemble(&doubled), Some(payload));
    }

    #[test]
    fn a_message_is_incomplete_until_every_fragment_arrives() {
        let payload: Vec<u8> = (0..8_000u32).map(|i| i as u8).collect();
        let frags = fragment(5, &payload, DGRAM);
        assert!(frags.len() > 2);
        // Withhold the last fragment: never completes.
        let mut r = Reassembler::new();
        for f in &frags[..frags.len() - 1] {
            assert_eq!(r.push(f), None);
        }
        // The withheld one completes it, tagged with its message id.
        assert_eq!(r.push(frags.last().unwrap()), Some((5, payload)));
    }

    #[test]
    fn a_newer_message_supersedes_an_incomplete_one() {
        let old: Vec<u8> = vec![0xAA; 5_000];
        let new: Vec<u8> = vec![0xBB; 5_000];
        let old_frags = fragment(10, &old, DGRAM);
        let new_frags = fragment(11, &new, DGRAM);
        let mut r = Reassembler::new();
        // A partial old message...
        for f in &old_frags[..old_frags.len() - 1] {
            assert_eq!(r.push(f), None);
        }
        // ...is abandoned when the newer message arrives in full.
        let mut done = None;
        for f in &new_frags {
            if let Some((_, msg)) = r.push(f) {
                done = Some(msg);
            }
        }
        assert_eq!(done, Some(new));
    }

    #[test]
    fn stragglers_from_an_old_message_are_ignored() {
        let old: Vec<u8> = vec![0xAA; 3_000];
        let new: Vec<u8> = vec![0xBB; 3_000];
        let old_frags = fragment(20, &old, DGRAM);
        let new_frags = fragment(21, &new, DGRAM);
        let mut r = Reassembler::new();
        // Complete and accept the new message first.
        let mut done = None;
        for f in &new_frags {
            if let Some((id, msg)) = r.push(f) {
                r.accept(id);
                done = Some(msg);
            }
        }
        assert_eq!(done, Some(new));
        // Late fragments from the old message never resurrect it.
        for f in &old_frags {
            assert_eq!(r.push(f), None);
        }
    }

    #[test]
    fn an_unaccepted_completion_does_not_wedge_later_messages() {
        // A datagram with a bogus, huge id (corruption or a hostile peer)
        // completes on its own but the caller can't decode it, so it's never
        // accepted. A later, lower-id legitimate message must still get through —
        // the watermark advances only on accept, so the bogus id can't wedge it.
        let mut r = Reassembler::new();
        let mut junk = Encoder::new();
        junk.uint(u64::MAX); // absurd id
        junk.uint(0);
        junk.uint(1);
        junk.raw(b"not a decodable message");
        let (jid, _) = r
            .push(&junk.into_vec())
            .expect("a one-fragment message completes");
        assert_eq!(jid, u64::MAX);
        // The caller's decode fails, so it does NOT accept(jid).

        // A normal message with a small id is still delivered.
        let real = b"the real payload".to_vec();
        let frags = fragment(7, &real, DGRAM);
        let mut done = None;
        for f in &frags {
            if let Some((id, msg)) = r.push(f) {
                r.accept(id);
                done = Some(msg);
            }
        }
        assert_eq!(done, Some(real));
    }

    #[test]
    fn a_zero_count_fragment_is_rejected() {
        let mut enc = Encoder::new();
        enc.uint(1); // id
        enc.uint(0); // index
        enc.uint(0); // count == 0: invalid
        enc.raw(b"x");
        assert_eq!(Reassembler::new().push(&enc.into_vec()), None);
    }

    #[test]
    fn an_index_past_the_count_is_rejected() {
        let mut enc = Encoder::new();
        enc.uint(1); // id
        enc.uint(3); // index 3...
        enc.uint(2); // ...but only 2 fragments: invalid
        enc.raw(b"x");
        assert_eq!(Reassembler::new().push(&enc.into_vec()), None);
    }

    #[test]
    fn a_count_past_the_cap_is_rejected() {
        let mut enc = Encoder::new();
        enc.uint(1);
        enc.uint(0);
        enc.uint(MAX_FRAGMENTS + 1); // over the fragment cap
        enc.raw(b"x");
        assert_eq!(Reassembler::new().push(&enc.into_vec()), None);
    }

    #[test]
    fn a_message_past_the_size_cap_never_completes() {
        // Two fragments whose payloads together exceed MAX_MESSAGE: the second is
        // refused, so the message never completes and the buffer stays bounded.
        let big = vec![0u8; MAX_MESSAGE];
        let mut r = Reassembler::new();
        let mut a = Encoder::new();
        a.uint(1);
        a.uint(0);
        a.uint(2);
        a.raw(&big);
        assert_eq!(r.push(&a.into_vec()), None); // fits the cap on its own
        let mut b = Encoder::new();
        b.uint(1);
        b.uint(1);
        b.uint(2);
        b.raw(b"one byte too many");
        assert_eq!(r.push(&b.into_vec()), None); // refused: over the cap, no completion
    }

    #[test]
    fn a_truncated_header_is_ignored() {
        // Not enough bytes for the three-varint header.
        assert_eq!(Reassembler::new().push(&[]), None);
        assert_eq!(Reassembler::new().push(&[0x80]), None); // dangling varint
    }

    #[test]
    fn push_never_panics_on_arbitrary_bytes() {
        // A crude fuzz: hostile datagrams must be dropped, never panic.
        let mut r = Reassembler::new();
        for seed in 0..2_000u32 {
            let len = (seed % 37) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|i| (seed.wrapping_mul(i as u32 + 1)) as u8)
                .collect();
            let _ = r.push(&bytes);
        }
    }
}
