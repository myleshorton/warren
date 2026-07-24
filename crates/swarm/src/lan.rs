//! LAN peer discovery — the sans-IO core.
//!
//! Two devices on the same local network find each other with **no backbone**: each
//! multicasts a small [`Beacon`] (who I am, where to reach me on the LAN, which blinded
//! topics I'm in), and tracks the peers it hears in a [`Peers`] set. The multicast socket +
//! timer live in the `driver`; here we provide the pure, testable pieces — the beacon codec
//! (signed, hostile-input-safe) and the provider-set logic (verify, topic-match, dedup, TTL).
//! See `docs/lan-discovery.md`.
//!
//! Privacy: only **blinded per-epoch topics** ride the beacon, so a passive LAN observer sees
//! rotating opaque hashes, never which channel a device is in. Safety: the beacon is signed so
//! garbage is cheap to drop, but a forged beacon can do no harm — the connection it points at
//! still runs an identity-pinned Noise handshake, so a wrong key is rejected there.

use std::collections::HashMap;
use std::net::SocketAddr;

use crypto::{hash, Hash, Keypair, PublicKey, Signature, HASH_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use thiserror::Error;
use wire::{Decoder, Encoder, WireError};

use crate::id::NodeId;
use crate::msg::{decode_addrs, encode_addrs};

/// Beacon wire version — bumped on any incompatible change to the encoding.
const BEACON_VERSION: u8 = 1;
/// Domain tag mixed into the signed bytes, so a beacon signature can't be mistaken for a
/// signature over anything else this key signs.
const BEACON_DOMAIN: &[u8] = b"warren-lan-beacon-v1";
/// A node advertises at most a few LAN addresses (multi-homed) and a few blinded topics
/// (current + previous epoch, a handful of channels). Hard caps keep `decode` from allocating
/// on a crafted count.
const MAX_ADDRS: usize = 8;
const MAX_TOPICS: usize = 8;

/// A LAN discovery beacon: the sender's identity key, its LAN data-socket address(es), and the
/// blinded topics it participates in — signed under that key.
#[derive(Debug, Clone)]
pub struct Beacon {
    /// The sender's identity public key; its node id is `hash(key)`.
    pub key: PublicKey,
    /// LAN data-socket addresses a peer can dial directly (no NAT on the segment).
    pub addrs: Vec<SocketAddr>,
    /// Blinded per-epoch topics (see `crypto::PublicKey::blinded_topic`) — matched against our
    /// own to recognize a same-channel peer without leaking the channel.
    pub topics: Vec<Hash>,
    /// Signature over `(domain, key, addrs, topics)`.
    pub sig: Signature,
}

impl Beacon {
    /// Build and sign a beacon for `keypair`.
    pub fn sign(keypair: &Keypair, addrs: Vec<SocketAddr>, topics: Vec<Hash>) -> Beacon {
        let key = keypair.public();
        let sig = keypair.sign(&signed_bytes(&key, &addrs, &topics));
        Beacon {
            key,
            addrs,
            topics,
            sig,
        }
    }

    /// The node id this beacon claims — `hash(key)`, exactly what `connect_direct` pins the
    /// Noise handshake to.
    pub fn node_id(&self) -> NodeId {
        NodeId::from_bytes(hash(self.key.as_bytes()))
    }

    /// Whether the signature checks out against the claimed key.
    pub fn verify(&self) -> bool {
        self.key
            .verify(
                &signed_bytes(&self.key, &self.addrs, &self.topics),
                &self.sig,
            )
            .is_ok()
    }

    /// Encode for the wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.u8(BEACON_VERSION);
        enc.raw(self.key.as_bytes());
        encode_addrs(&mut enc, &self.addrs);
        enc.uint(self.topics.len() as u64);
        for t in &self.topics {
            enc.raw(t);
        }
        enc.raw(&self.sig.to_bytes());
        enc.into_vec()
    }

    /// Decode a beacon from bytes. Never panics on hostile input; rejects an unknown version,
    /// over-long address/topic counts, or trailing bytes.
    pub fn decode(buf: &[u8]) -> Result<Beacon, LanError> {
        let mut dec = Decoder::new(buf);
        let version = dec.u8()?;
        if version != BEACON_VERSION {
            return Err(LanError::Version(version));
        }
        let key = PublicKey::from_bytes(&dec.array::<PUBLIC_KEY_LEN>()?)
            .map_err(|_| LanError::Malformed("invalid public key"))?;
        let addrs = decode_addrs(&mut dec).map_err(|_| LanError::Malformed("invalid addresses"))?;
        if addrs.len() > MAX_ADDRS {
            return Err(LanError::Malformed("too many addresses"));
        }
        let count = dec.uint()?;
        if count > MAX_TOPICS as u64 {
            return Err(LanError::Malformed("too many topics"));
        }
        if count > dec.remaining() as u64 / HASH_LEN as u64 {
            return Err(LanError::Malformed("topic count exceeds buffer"));
        }
        let mut topics = Vec::with_capacity(count as usize);
        for _ in 0..count {
            topics.push(dec.array::<HASH_LEN>()?);
        }
        let sig = Signature::from_bytes(dec.array::<SIGNATURE_LEN>()?);
        dec.finish()?;
        Ok(Beacon {
            key,
            addrs,
            topics,
            sig,
        })
    }
}

/// The exact bytes a beacon signs — domain-tagged and framed so distinct fields can't be
/// slid past each other. Both signing and verification go through this, so they can't diverge.
fn signed_bytes(key: &PublicKey, addrs: &[SocketAddr], topics: &[Hash]) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.bytes(BEACON_DOMAIN);
    enc.raw(key.as_bytes());
    encode_addrs(&mut enc, addrs);
    enc.uint(topics.len() as u64);
    for t in topics {
        enc.raw(t);
    }
    enc.into_vec()
}

/// A LAN-discovered peer: where it was last seen and when.
#[derive(Debug, Clone, Copy)]
struct Seen {
    addr: SocketAddr,
    last_ms: u64,
}

/// The set of same-channel peers heard on the LAN recently, keyed by node id — the provider
/// list a session prefers over the DHT. Sans-IO: the caller supplies the clock (`now_ms`).
#[derive(Debug, Default)]
pub struct Peers {
    seen: HashMap<NodeId, Seen>,
}

impl Peers {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold in a received beacon. Returns `Some((node_id, lan_addr))` when it's a peer worth
    /// dialing — the signature verifies, it isn't us (`me`), and it shares one of `our_topics`
    /// — recording/refreshing it in the set. `None` otherwise (garbage, self, or a different
    /// channel), touching nothing.
    pub fn observe(
        &mut self,
        beacon: &Beacon,
        now_ms: u64,
        me: NodeId,
        our_topics: &[Hash],
    ) -> Option<(NodeId, SocketAddr)> {
        if !beacon.verify() {
            return None;
        }
        let id = beacon.node_id();
        if id == me {
            return None; // our own beacon looped back
        }
        if !beacon.topics.iter().any(|t| our_topics.contains(t)) {
            return None; // not a channel we're in
        }
        let addr = *beacon.addrs.first()?; // primary LAN address
        self.seen.insert(
            id,
            Seen {
                addr,
                last_ms: now_ms,
            },
        );
        Some((id, addr))
    }

    /// The peers seen within `ttl_ms` of `now_ms` — the live LAN providers.
    pub fn fresh(&self, now_ms: u64, ttl_ms: u64) -> Vec<(NodeId, SocketAddr)> {
        self.seen
            .iter()
            .filter(|(_, s)| now_ms.saturating_sub(s.last_ms) <= ttl_ms)
            .map(|(id, s)| (*id, s.addr))
            .collect()
    }

    /// Drop entries older than `ttl_ms` (a peer that left the LAN stops beaconing).
    pub fn expire(&mut self, now_ms: u64, ttl_ms: u64) {
        self.seen
            .retain(|_, s| now_ms.saturating_sub(s.last_ms) <= ttl_ms);
    }
}

/// Why a beacon failed to decode.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LanError {
    /// The beacon's version byte isn't one we understand.
    #[error("unsupported beacon version {0}")]
    Version(u8),
    /// A field was malformed or a count exceeded its cap.
    #[error("malformed beacon: {0}")]
    Malformed(&'static str),
    /// The byte codec rejected the buffer.
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }

    fn beacon(seed: u8, topics: &[u8]) -> Beacon {
        let addrs = vec!["192.168.1.7:41800".parse().unwrap()];
        let topics = topics.iter().map(|&b| hash(&[b])).collect();
        Beacon::sign(&kp(seed), addrs, topics)
    }

    #[test]
    fn beacon_round_trips_and_verifies() {
        let b = beacon(1, &[10, 20]);
        let decoded = Beacon::decode(&b.encode()).unwrap();
        assert_eq!(decoded.key.to_bytes(), b.key.to_bytes());
        assert_eq!(decoded.addrs, b.addrs);
        assert_eq!(decoded.topics, b.topics);
        assert!(decoded.verify(), "a faithfully-decoded beacon verifies");
        assert_eq!(decoded.node_id(), b.node_id());
    }

    #[test]
    fn a_tampered_beacon_fails_to_verify() {
        let mut b = beacon(2, &[10]);
        // Change an advertised address the signature covers.
        b.addrs = vec!["10.0.0.9:1234".parse().unwrap()];
        assert!(!b.verify(), "mutating a signed field breaks the signature");
    }

    #[test]
    fn decode_rejects_bad_version_and_never_panics_on_garbage() {
        // Wrong version.
        let mut b = beacon(3, &[1]).encode();
        b[0] = 99;
        assert!(matches!(Beacon::decode(&b), Err(LanError::Version(99))));
        // Arbitrary / truncated bytes never panic.
        for len in 0..80usize {
            let junk: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let _ = Beacon::decode(&junk);
        }
    }

    #[test]
    fn observe_records_a_matching_peer_and_skips_others() {
        let me = beacon(1, &[]).node_id();
        let ours = vec![hash(&[10]), hash(&[20])];
        let mut peers = Peers::new();

        // A same-topic peer is recorded + returned.
        let friend = beacon(2, &[20, 30]);
        assert_eq!(
            peers.observe(&friend, 1000, me, &ours),
            Some((friend.node_id(), friend.addrs[0]))
        );
        assert_eq!(peers.fresh(1000, 5000).len(), 1);

        // A different-channel peer is ignored.
        let stranger = beacon(3, &[40, 50]);
        assert_eq!(peers.observe(&stranger, 1000, me, &ours), None);

        // Our own looped-back beacon is ignored.
        let mine = beacon(1, &[10]);
        assert_eq!(peers.observe(&mine, 1000, me, &ours), None);

        assert_eq!(
            peers.fresh(1000, 5000).len(),
            1,
            "only the friend is a provider"
        );
    }

    #[test]
    fn a_tampered_beacon_is_not_recorded() {
        let me = beacon(1, &[]).node_id();
        let ours = vec![hash(&[10])];
        let mut peers = Peers::new();
        let mut forged = beacon(2, &[10]);
        forged.sig = beacon(9, &[10]).sig; // wrong signature
        assert_eq!(peers.observe(&forged, 1, me, &ours), None);
        assert!(peers.fresh(1, 5000).is_empty());
    }

    #[test]
    fn providers_expire_after_the_ttl() {
        let me = beacon(1, &[]).node_id();
        let ours = vec![hash(&[10])];
        let mut peers = Peers::new();
        let friend = beacon(2, &[10]);
        peers.observe(&friend, 1000, me, &ours);

        assert_eq!(peers.fresh(4000, 5000).len(), 1, "within ttl");
        assert_eq!(
            peers.fresh(7000, 5000).len(),
            0,
            "past ttl (not yet expired)"
        );
        peers.expire(7000, 5000);
        assert!(
            peers.fresh(7000, 5000).is_empty(),
            "expired entries dropped"
        );

        // A fresh beacon revives the peer.
        peers.observe(&friend, 8000, me, &ours);
        assert_eq!(peers.fresh(8000, 5000).len(), 1);
    }
}
