//! Noise key agreement inside signed RPC envelopes; compact authenticated UDP after it.
use crate::protocol::{node_id, Packet, MAX_PACKET};
use crate::{NodeId, Time};
use crypto::PublicKey;
use snow::{HandshakeState, StatelessTransportState};
use std::collections::BTreeMap;
use std::net::SocketAddr;

const PARAMS: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
const MAGIC: &[u8] = b"WRE3\x01";
const HEADER: usize = 5 + 16 + 8;
const LIFETIME: u64 = 300_000;
const LIMIT: usize = 5120;

type Id = [u8; 16];

pub(crate) struct Sessions {
    entries: BTreeMap<Id, Session>,
    preferred: BTreeMap<(NodeId, SocketAddr), Id>,
}

struct Session {
    noise: StatelessTransportState,
    key: PublicKey,
    address: SocketAddr,
    expires: u64,
    sent: u64,
    replay: Window,
}

#[derive(Default)]
struct Window {
    highest: Option<u64>,
    bits: [u64; 16],
}

impl Window {
    fn rejects(&self, n: u64) -> bool {
        n == u64::MAX
            || self.highest.is_some_and(|h| {
                n <= h
                    && (h - n >= 1024 || self.bits[(n % 1024 / 64) as usize] & (1 << (n % 64)) != 0)
            })
    }

    fn record(&mut self, n: u64) {
        if let Some(h) = self.highest {
            if n > h {
                if n - h >= 1024 {
                    self.bits.fill(0);
                } else {
                    for i in h + 1..=n {
                        self.bits[(i % 1024 / 64) as usize] &= !(1 << (i % 64));
                    }
                }
            }
        }
        self.highest = Some(self.highest.map_or(n, |h| h.max(n)));
        self.bits[(n % 1024 / 64) as usize] |= 1 << (n % 64);
    }
}

fn handshake(packet: &Packet, initiator: bool) -> Option<HandshakeState> {
    let mut prologue = b"warren:dht-next:peer-session:v1".to_vec();
    prologue.extend_from_slice(node_id(packet.key).as_bytes());
    prologue.extend_from_slice(packet.destination.as_bytes());
    prologue.extend_from_slice(&packet.nonce);
    let builder = snow::Builder::new(PARAMS.parse().ok()?)
        .prologue(&prologue)
        .ok()?;
    if initiator {
        builder.build_initiator().ok()
    } else {
        builder.build_responder().ok()
    }
}

/// NN alone has no identity authentication. Both messages MUST travel inside
/// verified Ed25519 envelopes; the prologue binds their roles, identities and RPC.
pub(crate) fn start(packet: &mut Packet) -> Option<HandshakeState> {
    #[cfg(feature = "diagnostics")]
    let _span = crate::diagnostics::span(crate::diagnostics::Region::Handshake);
    let mut state = handshake(packet, true)?;
    let mut message = [0; 48];
    let n = state.write_message(&[], &mut message).ok()?;
    packet.exchange = message[..n].to_vec();
    Some(state)
}

impl Sessions {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            preferred: BTreeMap::new(),
        }
    }

    pub fn available(&self, peer: NodeId, addr: SocketAddr, now: Time) -> bool {
        self.preferred
            .get(&(peer, addr))
            .and_then(|id| self.entries.get(id))
            .is_some_and(|s| s.expires > now.monotonic_ms && s.sent < u64::MAX)
    }

    pub fn forget_preferred(&mut self, peer: NodeId, addr: SocketAddr) {
        self.preferred.remove(&(peer, addr));
    }

    fn room_for(&self, key: PublicKey, address: SocketAddr, now: Time) -> bool {
        self.entries.len() < LIMIT
            && self
                .entries
                .values()
                .filter(|s| s.expires > now.monotonic_ms && s.key == key)
                .count()
                < 8
            && self
                .entries
                .values()
                .filter(|s| {
                    s.expires > now.monotonic_ms
                        && crate::routing::network_prefix(s.address)
                            == crate::routing::network_prefix(address)
                })
                .count()
                < 128
    }

    fn install(
        &mut self,
        state: HandshakeState,
        key: PublicKey,
        address: SocketAddr,
        now: Time,
        confirmed: bool,
    ) -> Option<()> {
        if !self.room_for(key, address, now) {
            return None;
        }
        let id: Id = state.get_handshake_hash()[..16].try_into().ok()?;
        let noise = state.into_stateless_transport_mode().ok()?;
        // Never reset counters on an existing key, even on a repeated handshake.
        if self.entries.contains_key(&id) {
            return None;
        }
        self.entries.insert(
            id,
            Session {
                noise,
                key,
                address,
                expires: now.monotonic_ms.saturating_add(LIFETIME),
                sent: 0,
                replay: Window::default(),
            },
        );
        if confirmed {
            self.preferred.insert((node_id(key), address), id);
        }
        Some(())
    }

    pub fn accept(&mut self, packet: &Packet, address: SocketAddr, now: Time) -> Option<Vec<u8>> {
        if packet.exchange.len() != 32 || !self.room_for(packet.key, address, now) {
            return None;
        }
        #[cfg(feature = "diagnostics")]
        let _span = crate::diagnostics::span(crate::diagnostics::Region::Handshake);
        let mut state = handshake(packet, false)?;
        let mut empty = [0; 0];
        if state.read_message(&packet.exchange, &mut empty).ok()? != 0 {
            return None;
        }
        let mut message = [0; 48];
        let n = state.write_message(&[], &mut message).ok()?;
        self.install(state, packet.key, address, now, false)?;
        Some(message[..n].to_vec())
    }

    pub fn finish(
        &mut self,
        mut state: HandshakeState,
        packet: &Packet,
        address: SocketAddr,
        now: Time,
    ) -> Option<()> {
        if packet.exchange.len() != 48 {
            return None;
        }
        #[cfg(feature = "diagnostics")]
        let _span = crate::diagnostics::span(crate::diagnostics::Region::Handshake);
        let mut empty = [0; 0];
        if state.read_message(&packet.exchange, &mut empty).ok()? != 0 {
            return None;
        }
        self.install(state, packet.key, address, now, true)
    }

    pub fn encode(&mut self, packet: &Packet, address: SocketAddr, now: Time) -> Option<Vec<u8>> {
        if !packet.exchange.is_empty() {
            return None;
        }
        let id = *self.preferred.get(&(packet.destination, address))?;
        let s = self.entries.get_mut(&id)?;
        if s.expires <= now.monotonic_ms || s.sent == u64::MAX {
            return None;
        }
        let payload = packet.compact();
        if HEADER + payload.len() + 16 > MAX_PACKET {
            return None;
        }
        let mut bytes = vec![0; HEADER + payload.len() + 16];
        bytes[..5].copy_from_slice(MAGIC);
        bytes[5..21].copy_from_slice(&id);
        bytes[21..HEADER].copy_from_slice(&s.sent.to_le_bytes());
        // Reserve the nonce before encryption; failures must never reuse it.
        let nonce = s.sent;
        s.sent += 1;
        let n = {
            #[cfg(feature = "diagnostics")]
            let _span = crate::diagnostics::span(crate::diagnostics::Region::Seal);
            s.noise
                .write_message(nonce, &payload, &mut bytes[HEADER..])
                .ok()?
        };
        bytes.truncate(HEADER + n);
        Some(bytes)
    }

    pub fn decode(
        &mut self,
        bytes: &[u8],
        address: SocketAddr,
        destination: NodeId,
        now: Time,
    ) -> Option<Packet> {
        if bytes.len() < HEADER + 16 || bytes.len() > MAX_PACKET || &bytes[..5] != MAGIC {
            return None;
        }
        let id: Id = bytes[5..21].try_into().ok()?;
        let nonce = u64::from_le_bytes(bytes[21..HEADER].try_into().ok()?);
        let s = self.entries.get_mut(&id)?;
        if s.address != address || s.expires <= now.monotonic_ms || s.replay.rejects(nonce) {
            return None;
        }
        let mut payload = vec![0; bytes.len() - HEADER - 16];
        let n = {
            #[cfg(feature = "diagnostics")]
            let _span = crate::diagnostics::span(crate::diagnostics::Region::Open);
            s.noise
                .read_message(nonce, &bytes[HEADER..], &mut payload)
                .ok()?
        };
        // An unauthenticated large nonce must not advance the replay window.
        s.replay.record(nonce);
        // Receiving transport proves the initiator obtained our handshake reply.
        self.preferred.insert((node_id(s.key), address), id);
        Packet::from_compact(&payload[..n], s.key, destination)
    }

    pub fn expire(&mut self, now: Time) {
        self.entries.retain(|_, s| s.expires > now.monotonic_ms);
        self.preferred.retain(|_, id| self.entries.contains_key(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Body;
    use crypto::Keypair;

    fn key(n: u8) -> PublicKey {
        Keypair::from_seed(&[n; 32]).public()
    }
    fn addr(n: u8) -> SocketAddr {
        format!("198.51.100.{n}:4000").parse().unwrap()
    }
    fn packet() -> Packet {
        Packet {
            key: key(1),
            destination: node_id(key(2)),
            server: false,
            nonce: [7; 32],
            epoch: 3,
            cookie: [8; 32],
            body: Body::Probe,
            exchange: Vec::new(),
        }
    }
    fn connected() -> (Sessions, Sessions, Packet) {
        let now = Time::new(100_000, 100);
        let mut a = Sessions::new();
        let mut b = Sessions::new();
        let mut p = packet();
        let state = start(&mut p).unwrap();
        assert_eq!(p.exchange.len(), 32);
        let exchange = b.accept(&p, addr(1), now).unwrap();
        assert_eq!(exchange.len(), 48);
        let reply = Packet {
            key: key(2),
            destination: node_id(key(1)),
            body: Body::Ack,
            exchange,
            ..p.clone()
        };
        a.finish(state, &reply, addr(2), now).unwrap();
        p.exchange.clear();
        (a, b, p)
    }

    #[test]
    fn one_identity_cannot_fill_the_transport_table() {
        let mut receiver = Sessions::new();
        let now = Time::new(100_000, 100);
        for n in 0..9 {
            let mut p = packet();
            p.nonce[0] = n;
            start(&mut p).unwrap();
            assert_eq!(receiver.accept(&p, addr(1), now).is_some(), n < 8);
        }
        assert_eq!(receiver.entries.len(), 8);
        let mut other = packet();
        other.key = key(3);
        start(&mut other).unwrap();
        assert!(receiver.accept(&other, addr(3), now).is_some());
        receiver.expire(Time::new(400_001, 400));
        let mut p = packet();
        start(&mut p).unwrap();
        assert!(receiver
            .accept(&p, addr(1), Time::new(400_001, 400))
            .is_some());
    }

    #[test]
    fn compact_transport_encrypts_and_accepts_reordering_once() {
        let (mut a, mut b, p) = connected();
        let now = Time::new(100_100, 100);
        let packets: Vec<_> = (0..3)
            .map(|_| a.encode(&p, addr(2), now).unwrap())
            .collect();
        assert_eq!(packets[0].len(), 119);
        assert!(Packet::decode(&packets[0]).is_none());
        assert!(!packets[0].windows(32).any(|w| w == p.cookie));
        for i in [2, 0, 1] {
            let decoded = b
                .decode(&packets[i], addr(1), node_id(key(2)), now)
                .unwrap();
            assert_eq!(decoded.key, p.key);
            assert_eq!(decoded.body, p.body);
            assert_eq!(decoded.cookie, p.cookie);
            assert!(b
                .decode(&packets[i], addr(1), node_id(key(2)), now)
                .is_none());
        }
    }

    #[test]
    fn forged_counter_header_ciphertext_or_endpoint_does_not_poison_replay_window() {
        let (mut a, mut b, p) = connected();
        let now = Time::new(100_100, 100);
        let bytes = a.encode(&p, addr(2), now).unwrap();
        for index in [0, 5, 21, 28, 29, bytes.len() - 1] {
            let mut bad = bytes.clone();
            bad[index] ^= 128;
            assert!(b.decode(&bad, addr(1), node_id(key(2)), now).is_none());
        }
        assert!(b.decode(&bytes, addr(3), node_id(key(2)), now).is_none());
        assert!(a.decode(&bytes, addr(2), node_id(key(1)), now).is_none());
        assert!(b.decode(&bytes, addr(1), node_id(key(2)), now).is_some());
    }

    #[test]
    fn handshake_transcript_binds_both_identities_and_rpc_nonce() {
        for change in 0..3 {
            let mut p = packet();
            let state = start(&mut p).unwrap();
            let mut modified = p.clone();
            match change {
                0 => modified.key = key(3),
                1 => modified.destination = node_id(key(3)),
                _ => modified.nonce[0] ^= 1,
            }
            let now = Time::new(100_000, 100);
            let exchange = Sessions::new().accept(&modified, addr(1), now).unwrap();
            let reply = Packet {
                key: key(2),
                exchange,
                ..p
            };
            assert!(Sessions::new()
                .finish(state, &reply, addr(2), now)
                .is_none());
        }
    }

    #[test]
    fn lost_rotation_reply_preserves_confirmed_keys_until_key_confirmation() {
        let (mut a, mut b, mut p) = connected();
        let now = Time::new(100_100, 100);
        assert!(!b.available(node_id(key(1)), addr(1), now));
        let first = a.encode(&p, addr(2), now).unwrap();
        b.decode(&first, addr(1), node_id(key(2)), now).unwrap();
        let old = b.preferred[&(node_id(key(1)), addr(1))];
        p.nonce[0] ^= 1;
        let state = start(&mut p).unwrap();
        let exchange = b.accept(&p, addr(1), now).unwrap();
        assert_eq!(b.preferred[&(node_id(key(1)), addr(1))], old);
        let mut reply = Packet {
            key: key(2),
            destination: node_id(key(1)),
            body: Body::Ack,
            exchange: Vec::new(),
            ..p.clone()
        };
        let in_flight = b.encode(&reply, addr(1), now).unwrap();
        assert!(a
            .decode(&in_flight, addr(2), node_id(key(1)), now)
            .is_some());
        reply.exchange = exchange;
        a.finish(state, &reply, addr(2), now).unwrap();
        p.exchange.clear();
        let confirmation = a.encode(&p, addr(2), now).unwrap();
        b.decode(&confirmation, addr(1), node_id(key(2)), now)
            .unwrap();
        assert_ne!(b.preferred[&(node_id(key(1)), addr(1))], old);
    }

    #[test]
    fn lifetime_and_counter_exhaustion_fail_closed() {
        let (mut a, mut b, p) = connected();
        let now = Time::new(100_100, 100);
        let bytes = a.encode(&p, addr(2), now).unwrap();
        a.entries.values_mut().next().unwrap().sent = u64::MAX - 1;
        assert!(a.encode(&p, addr(2), now).is_some());
        assert!(a.encode(&p, addr(2), now).is_none());
        let expired = Time::new(400_000, 100);
        assert!(b
            .decode(&bytes, addr(1), node_id(key(2)), expired)
            .is_none());
        b.expire(expired);
        assert!(b.entries.is_empty());
        assert!(b.preferred.is_empty());
    }

    #[test]
    fn replay_window_handles_large_advances_and_lower_boundary() {
        let mut w = Window::default();
        w.record(0);
        w.record(1024);
        assert!(w.rejects(0));
        assert!(!w.rejects(1));
        w.record(1);
        assert!(w.rejects(1));
        w.record(100_000);
        assert!(w.rejects(1024));
        assert!(!w.rejects(99_999));
        assert!(w.rejects(u64::MAX));
    }
}
