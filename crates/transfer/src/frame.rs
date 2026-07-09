//! Framing + selective-repeat reliability over the datagram [`driver::Channel`].
//!
//! A `Channel` carries datagrams, each bounded by [`MAX_DATAGRAM`](crate::MAX_DATAGRAM);
//! a single [`sync::Message`](sync) — a blob chunk, a feed block with its proof,
//! or a manifest — can be larger. This module is the seam that lets a message
//! span several datagrams and repairs individual losses:
//!
//! - [`fragment`] splits an encoded message into datagram-sized [`Packet::Data`]
//!   pieces, each tagged with a message id and its index;
//! - a [`Reassembler`] collects those pieces back into the original bytes and
//!   reports, via [`Reassembler::missing`], which indices are still outstanding;
//! - a [`Packet::Nack`] carries that missing set back to the sender, which
//!   resends only those fragments (rather than the whole message).
//!
//! It is **sans-IO**: pure over `&[u8]`, no sockets and no clock, so everything —
//! reassembly under loss, reordering, duplication, hostile headers, and a full
//! NACK-driven repair loop — is exercised by deterministic unit tests. The
//! crate's `Wire` pumps these packets over a real channel and supplies the
//! timing (when a stalled receiver decides to NACK).

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

/// Most missing indices to list in one [`Packet::Nack`]. Keeps a NACK within a
/// single datagram (≈256 three-byte varints plus a small header, well under the
/// send size); a receiver missing more pages across successive NACKs.
pub const NACK_MAX_INDICES: usize = 256;

/// Bytes reserved in each datagram for a `Data` header: a 1-byte tag plus three
/// [`u64`] varints (message id, fragment index, fragment count), each at most 10
/// bytes. A conservative upper bound, so a fragment's header-plus-payload never
/// exceeds the datagram size it was split for.
const HEADER_BUDGET: usize = 32;

const TAG_DATA: u8 = 0;
const TAG_NACK: u8 = 1;

/// A datagram on the channel: either one fragment of a message, or a request to
/// resend fragments that didn't arrive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// One fragment of message `id`: fragment `index` of `count`, carrying
    /// `payload` bytes.
    Data {
        /// The message this fragment belongs to.
        id: u64,
        /// This fragment's position in the message.
        index: u64,
        /// Total fragments the message was split into.
        count: u64,
        /// The fragment's slice of the message bytes.
        payload: Vec<u8>,
    },
    /// A request to resend the listed fragment `indices` of message `id` — the
    /// ones the receiver is still missing.
    Nack {
        /// The message whose fragments are being requested.
        id: u64,
        /// The missing fragment indices to resend.
        indices: Vec<u64>,
    },
}

impl Packet {
    /// Decode a datagram, or `None` if it isn't a well-formed packet (junk, a
    /// truncated header, or an abusive count) — the transport treats such
    /// datagrams as noise, never a failure.
    pub fn decode(datagram: &[u8]) -> Option<Packet> {
        let mut dec = Decoder::new(datagram);
        match dec.u8().ok()? {
            TAG_DATA => {
                let id = dec.uint().ok()?;
                let index = dec.uint().ok()?;
                let count = dec.uint().ok()?;
                let remaining = dec.remaining();
                let payload = dec.raw(remaining).ok()?.to_vec();
                Some(Packet::Data {
                    id,
                    index,
                    count,
                    payload,
                })
            }
            TAG_NACK => {
                let id = dec.uint().ok()?;
                let k = dec.uint().ok()?;
                // A sender never puts more than NACK_MAX_INDICES in one NACK (it
                // pages), so reject anything larger — this keeps parsing
                // allocation-bounded under hostile input, well below what
                // `remaining` bytes alone would allow (~65k u64s otherwise).
                if k > NACK_MAX_INDICES as u64 {
                    return None;
                }
                // `k` is now bounded (≤ 256), so pre-allocate exactly it — small,
                // and no reallocations while reading.
                let mut indices = Vec::with_capacity(k as usize);
                for _ in 0..k {
                    indices.push(dec.uint().ok()?);
                }
                dec.finish().ok()?;
                Some(Packet::Nack { id, indices })
            }
            _ => None,
        }
    }
}

/// Encode a `Data` datagram for one fragment.
fn data_datagram(id: u64, index: u64, count: u64, payload: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(TAG_DATA);
    enc.uint(id);
    enc.uint(index);
    enc.uint(count);
    enc.raw(payload);
    enc.into_vec()
}

/// Encode a `Nack` datagram asking the sender to resend `indices` of message
/// `id`. The caller keeps `indices` within [`NACK_MAX_INDICES`] so it fits one
/// datagram.
pub fn nack_datagram(id: u64, indices: &[u64]) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.u8(TAG_NACK);
    enc.uint(id);
    enc.uint(indices.len() as u64);
    for &i in indices {
        enc.uint(i);
    }
    enc.into_vec()
}

/// Split `payload` into `Data` fragments that each fit in a `datagram`-byte
/// packet, tagged with `msg_id` so a [`Reassembler`] can group and order them.
/// Yields them lazily — one at a time — so the caller can send each as it's built
/// rather than buffer the whole set (a large message would otherwise peak at a
/// second copy of itself). Always yields at least one fragment (an empty payload
/// yields a single empty one).
///
/// `datagram` must exceed `HEADER_BUDGET` — otherwise the header alone would fill
/// (or overflow) a fragment and the "fits in `datagram` bytes" guarantee couldn't
/// hold. Callers pass the crate's `FRAGMENT`, far larger; the assertion documents
/// the precondition for any future caller.
pub fn fragment(
    msg_id: u64,
    payload: &[u8],
    datagram: usize,
) -> impl Iterator<Item = Vec<u8>> + '_ {
    debug_assert!(
        datagram > HEADER_BUDGET,
        "datagram ({datagram}) must exceed the fragment header budget ({HEADER_BUDGET})"
    );
    let budget = datagram.saturating_sub(HEADER_BUDGET).max(1);
    let count = payload.len().div_ceil(budget).max(1);
    (0..count).map(move |i| {
        let start = i * budget;
        let end = ((i + 1) * budget).min(payload.len());
        data_datagram(msg_id, i as u64, count as u64, &payload[start..end])
    })
}

/// Build just the `index`-th `Data` fragment of `payload`, or `None` if `index`
/// is past the fragment count. Lets a sender answer a NACK by rebuilding only the
/// requested fragments, without materializing (and allocating) the rest.
pub fn fragment_at(msg_id: u64, payload: &[u8], datagram: usize, index: u64) -> Option<Vec<u8>> {
    debug_assert!(datagram > HEADER_BUDGET);
    let budget = datagram.saturating_sub(HEADER_BUDGET).max(1);
    let count = payload.len().div_ceil(budget).max(1) as u64;
    if index >= count {
        return None;
    }
    let i = index as usize;
    let start = i * budget;
    let end = ((i + 1) * budget).min(payload.len());
    Some(data_datagram(msg_id, index, count, &payload[start..end]))
}

/// The fragments of a message a receiver is still missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing {
    /// The message being reassembled.
    pub id: u64,
    /// Indices not yet received, ascending.
    pub indices: Vec<u64>,
}

/// Collects the fragments of a message and tracks which are still missing so the
/// receiver can NACK for them. Because the transfer loop is stop-and-wait, only
/// one message is in flight per direction, so this tracks one at a time and
/// follows the newest id it sees.
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
    /// Total distinct fragments ever stored, over this reassembler's whole life.
    /// Monotonic — it doesn't reset when the current message is superseded — so
    /// the driver can use it as a progress signal that survives an id switch
    /// (where the in-progress fragment count would otherwise drop).
    stored: usize,
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

    /// Feed a decoded `Data` fragment. Returns `Some((id, payload))` when it
    /// completes a message — the caller decodes `payload` and, on success, calls
    /// [`Reassembler::accept`] with `id` to commit it. Returns `None` while more
    /// fragments are needed. Abusive framing (a count or size past the caps) or a
    /// straggler (at or below the accepted watermark) is dropped.
    pub fn push_data(
        &mut self,
        id: u64,
        index: u64,
        count: u64,
        payload: Vec<u8>,
    ) -> Option<(u64, Vec<u8>)> {
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
        let is_new = !partial.frags.contains_key(&index);
        if is_new {
            if partial.bytes + payload.len() > MAX_MESSAGE {
                return None; // would exceed the reassembly cap: refuse to buffer
            }
            partial.bytes += payload.len();
            partial.frags.insert(index, payload); // move in — no re-copy
        }
        // Complete once every index in [0, count) is present: `frags` holds
        // `count` distinct in-range indices exactly when the message is whole.
        let complete = partial.frags.len() == partial.count;

        if is_new {
            self.stored += 1; // a fresh fragment landed: real progress
        }
        // The watermark is *not* advanced here — only when the caller accepts the
        // decoded payload — so a bogus id can't wedge later messages.
        if complete {
            let partial = self.current.take().expect("present");
            let mut out = Vec::with_capacity(partial.bytes);
            for i in 0..partial.count {
                out.extend_from_slice(&partial.frags[&i]);
            }
            return Some((partial.id, out));
        }
        None
    }

    /// Decode `datagram` as a `Data` packet and feed it in. A convenience over
    /// [`Reassembler::push_data`] for tests; non-`Data`/undecodable datagrams are
    /// ignored. Production decodes the [`Packet`] once in `Wire` and routes it.
    #[cfg(test)]
    pub fn push(&mut self, datagram: &[u8]) -> Option<(u64, Vec<u8>)> {
        match Packet::decode(datagram)? {
            Packet::Data {
                id,
                index,
                count,
                payload,
            } => self.push_data(id, index, count, payload),
            Packet::Nack { .. } => None,
        }
    }

    /// Total distinct fragments stored over this reassembler's life — monotonic,
    /// so an interval that stored at least one new fragment shows as progress
    /// even if the in-progress message was superseded (which resets the current
    /// fragment count but not this).
    pub fn stored(&self) -> usize {
        self.stored
    }

    /// The fragments still missing from the message in progress, or `None` if
    /// nothing is being reassembled. Capped at [`NACK_MAX_INDICES`] — the caller
    /// NACKs one datagram's worth at a time and pages the rest across intervals,
    /// so building the full set (up to `count`, which hostile framing could push
    /// toward `MAX_FRAGMENTS`) would be pointless allocation.
    pub fn missing(&self) -> Option<Missing> {
        let partial = self.current.as_ref()?;
        let indices = (0..partial.count as u64)
            .filter(|i| !partial.frags.contains_key(&(*i as usize)))
            .take(NACK_MAX_INDICES)
            .collect();
        Some(Missing {
            id: partial.id,
            indices,
        })
    }

    /// Commit `id` once the caller has validated the message [`Reassembler::push_data`]
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
    use std::collections::HashSet;

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
        let frags: Vec<Vec<u8>> = fragment(1, &payload, DGRAM).collect();
        assert_eq!(frags.len(), 1);
        assert_eq!(reassemble(&frags), Some(payload));
    }

    #[test]
    fn an_empty_payload_roundtrips_as_one_empty_fragment() {
        let frags: Vec<Vec<u8>> = fragment(7, &[], DGRAM).collect();
        assert_eq!(frags.len(), 1);
        assert_eq!(reassemble(&frags), Some(Vec::new()));
    }

    #[test]
    fn a_large_message_spans_many_fragments_and_roundtrips() {
        let payload: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        let frags: Vec<Vec<u8>> = fragment(2, &payload, DGRAM).collect();
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
        let mut frags: Vec<Vec<u8>> = fragment(3, &payload, DGRAM).collect();
        frags.reverse();
        assert_eq!(reassemble(&frags), Some(payload));
    }

    #[test]
    fn duplicate_fragments_are_harmless() {
        let payload: Vec<u8> = (0..5_000u32).map(|i| i as u8).collect();
        let frags: Vec<Vec<u8>> = fragment(4, &payload, DGRAM).collect();
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
        let frags: Vec<Vec<u8>> = fragment(5, &payload, DGRAM).collect();
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
    fn missing_reports_the_gaps_then_none_when_whole() {
        let payload: Vec<u8> = (0..6_000u32).map(|i| i as u8).collect();
        let frags: Vec<Vec<u8>> = fragment(9, &payload, DGRAM).collect();
        let n = frags.len();
        assert!(n >= 4, "need several fragments for a meaningful gap");

        let mut r = Reassembler::new();
        // Deliver all but indices 1 and 3.
        for (i, f) in frags.iter().enumerate() {
            if i != 1 && i != 3 {
                r.push(f);
            }
        }
        let missing = r.missing().expect("a message is in progress");
        assert_eq!(missing.id, 9);
        assert_eq!(missing.indices, vec![1, 3]);

        // Delivering the gaps completes it, and nothing is in progress after.
        r.push(&frags[1]);
        let (id, msg) = r.push(&frags[3]).expect("the last gap completes it");
        r.accept(id);
        assert_eq!(msg, payload);
        assert_eq!(r.missing(), None);
    }

    #[test]
    fn a_newer_message_supersedes_an_incomplete_one() {
        let old: Vec<u8> = vec![0xAA; 5_000];
        let new: Vec<u8> = vec![0xBB; 5_000];
        let old_frags: Vec<Vec<u8>> = fragment(10, &old, DGRAM).collect();
        let new_frags: Vec<Vec<u8>> = fragment(11, &new, DGRAM).collect();
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
        let old_frags: Vec<Vec<u8>> = fragment(20, &old, DGRAM).collect();
        let new_frags: Vec<Vec<u8>> = fragment(21, &new, DGRAM).collect();
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
        let junk = data_datagram(u64::MAX, 0, 1, b"not a decodable message");
        let (jid, _) = r.push(&junk).expect("a one-fragment message completes");
        assert_eq!(jid, u64::MAX);
        // The caller's decode fails, so it does NOT accept(jid).

        // A normal message with a small id is still delivered.
        let real = b"the real payload".to_vec();
        let frags: Vec<Vec<u8>> = fragment(7, &real, DGRAM).collect();
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
    fn push_data_rejects_abusive_framing() {
        let mut r = Reassembler::new();
        assert_eq!(r.push_data(1, 0, 0, b"x".to_vec()), None); // count == 0
        assert_eq!(r.push_data(1, 3, 2, b"x".to_vec()), None); // index past count
        assert_eq!(r.push_data(1, 0, MAX_FRAGMENTS + 1, b"x".to_vec()), None); // count past cap
    }

    #[test]
    fn a_message_past_the_size_cap_never_completes() {
        // Two fragments whose payloads together exceed MAX_MESSAGE: the second is
        // refused, so the message never completes and the buffer stays bounded.
        let mut r = Reassembler::new();
        assert_eq!(r.push_data(1, 0, 2, vec![0u8; MAX_MESSAGE]), None); // fits the cap alone
        assert_eq!(r.push_data(1, 1, 2, b"one byte too many".to_vec()), None); // over the cap
    }

    #[test]
    fn fragment_at_matches_fragment_and_bounds_the_index() {
        let payload: Vec<u8> = (0..7_000u32).map(|i| i as u8).collect();
        let all: Vec<Vec<u8>> = fragment(3, &payload, DGRAM).collect();
        for (i, f) in all.iter().enumerate() {
            assert_eq!(fragment_at(3, &payload, DGRAM, i as u64).as_ref(), Some(f));
        }
        assert_eq!(fragment_at(3, &payload, DGRAM, all.len() as u64), None); // past the end
    }

    #[test]
    fn packet_roundtrips() {
        let data = Packet::Data {
            id: 42,
            index: 3,
            count: 9,
            payload: b"some bytes".to_vec(),
        };
        assert_eq!(
            Packet::decode(&data_datagram(42, 3, 9, b"some bytes")),
            Some(data)
        );

        let nack = Packet::Nack {
            id: 42,
            indices: vec![1, 4, 5],
        };
        assert_eq!(Packet::decode(&nack_datagram(42, &[1, 4, 5])), Some(nack));
    }

    #[test]
    fn a_truncated_or_unknown_packet_is_ignored() {
        assert_eq!(Packet::decode(&[]), None); // no tag
        assert_eq!(Packet::decode(&[TAG_DATA]), None); // tag but no header
        assert_eq!(Packet::decode(&[0x7f]), None); // unknown tag
                                                   // A Nack claiming an absurd index count is refused before allocating.
        let mut enc = Encoder::new();
        enc.u8(TAG_NACK);
        enc.uint(1);
        enc.uint(MAX_FRAGMENTS + 1);
        assert_eq!(Packet::decode(&enc.into_vec()), None);
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
            let _ = Packet::decode(&bytes);
        }
    }

    /// A lossy pipe: `deliver` drops a datagram when its running index is in the
    /// drop schedule, modelling a link that loses specific packets.
    struct Lossy {
        sent: usize,
        drop: HashSet<usize>,
    }
    impl Lossy {
        fn new(drop: &[usize]) -> Self {
            Self {
                sent: 0,
                drop: drop.iter().copied().collect(),
            }
        }
        /// Returns the datagram if it survives, `None` if this one is dropped.
        fn deliver<'a>(&mut self, datagram: &'a [u8]) -> Option<&'a [u8]> {
            let n = self.sent;
            self.sent += 1;
            (!self.drop.contains(&n)).then_some(datagram)
        }
    }

    #[test]
    fn selective_repeat_recovers_a_lossy_transfer() {
        // End-to-end repair, purely: a large message is fragmented and delivered
        // over a lossy pipe; the receiver NACKs the gaps and the sender resends
        // only those, until the message is whole — resending far fewer datagrams
        // than the whole message.
        let msg: Vec<u8> = (0..40_000u32).map(|i| (i * 31) as u8).collect();
        let id = 1;
        let all: Vec<Vec<u8>> = fragment(id, &msg, DGRAM).collect();
        let total = all.len();
        assert!(total > 20, "want a message with many fragments");

        // Drop a scattered handful on the first delivery, and one NACK-repair
        // datagram too (so a fragment needs re-repairing).
        let mut link = Lossy::new(&[2, 5, 9, 14, 19, total]); // `total` = first repair pkt
        let mut r = Reassembler::new();
        let mut resent = 0;

        // First pass: send every fragment.
        let mut done = None;
        for f in &all {
            if let Some(d) = link.deliver(f) {
                if let Some((mid, bytes)) = r.push(d) {
                    r.accept(mid);
                    done = Some(bytes);
                }
            }
        }

        // Repair rounds: NACK the gaps, resend just those, until complete.
        let mut rounds = 0;
        while done.is_none() {
            rounds += 1;
            assert!(rounds < 100, "repair should converge");
            let missing = r.missing().expect("still in progress");
            assert_eq!(missing.id, id);
            // Sender resends exactly the requested fragments (as `resend` does).
            for &idx in &missing.indices {
                let f = fragment_at(id, &msg, DGRAM, idx).expect("index in range");
                resent += 1;
                if let Some(d) = link.deliver(&f) {
                    if let Some((mid, bytes)) = r.push(d) {
                        r.accept(mid);
                        done = Some(bytes);
                    }
                }
            }
        }

        assert_eq!(done, Some(msg));
        // Repair resent only a small fraction — not the whole message again.
        assert!(
            resent < total / 2,
            "repair resent {resent} of {total} fragments; expected only the lost few"
        );
    }
}
