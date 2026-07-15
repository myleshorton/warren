//! A Noise-encrypted, identity-bound wrapper around a punched datagram [`Link`].
//!
//! Warren's punched [`driver::Channel`] is a bare UDP path: plaintext, and
//! authenticated only by IP:port (the OS drops datagrams from any other source,
//! but a coordinator or an on-path adversary still sees — and could forge — every
//! byte). [`NoiseLink`] upgrades it in place to an **AEAD-encrypted, forward-secret,
//! mutually-authenticated** channel with a Noise `XX` handshake
//! (`Noise_XX_25519_ChaChaPoly_BLAKE2s`), then presents the same `Link` seam to the
//! transfer engine above it — so feeds and blobs stream unchanged, now confidential
//! and tamper-evident.
//!
//! # Identity binding
//!
//! A DHT node's id is `hash(ed25519 public key)` (see [`driver::Node`]). Noise `XX`
//! authenticates a *per-connection X25519 static* by DH, which says nothing about
//! that node id on its own. To bind the two, each side sends a [`NodeCert`] in its
//! handshake payload: its Ed25519 public key, the X25519 static it is using for
//! *this* connection, and a role- and protocol-domain-separated Ed25519 signature
//! over that static. After the handshake both sides check the signature and that the
//! signed static equals the
//! one Noise authenticated by DH (`get_remote_static`) — so a peer proves it holds
//! the Ed25519 secret behind its node id *and* controls the Noise static, with no
//! way to relay someone else's identity. The **dialer additionally** pins the
//! result to the node id it dialed: `hash(peer ed_pub) == target`, else the connect
//! fails with [`io::ErrorKind::PermissionDenied`] — you always reach exactly who
//! you asked for, or no one.
//!
//! # Unreliable transport
//!
//! The channel is lossy, unordered UDP, so the transport cipher runs in snow's
//! **stateless** mode: every transport datagram carries a type byte and an explicit
//! 8-byte little-endian nonce, and the sender counts its own sends from zero. A
//! lost, reordered, duplicated, or injected datagram therefore never desynchronizes
//! the cipher — the recipient decrypts each datagram independently by the nonce on
//! the wire — which is exactly what lets the transfer layer's selective-repeat
//! repair run *over* encryption. A 65,536-packet sliding replay window discards a
//! nonce already accepted (while preserving wide UDP reordering), and forged or
//! malformed datagrams are treated as packet loss rather than fatal socket errors.
//!
//! The three-message handshake is made reliable by a retransmit loop: the initiator
//! resends message 1 until message 2 arrives, and the responder resends message 2
//! until message 3 arrives (a stray duplicate of an earlier message is a lost-reply
//! signal that triggers an immediate resend). Because bare `XX` has no fourth
//! message, the responder sends an authenticated transport acknowledgment;
//! the initiator retransmits its cached message 3 until that arrives. The responder
//! retains the message-3/ACK pair so a duplicate message 3 can recover a lost ACK
//! while the application waits for its first request. Handshake and transport
//! datagrams carry distinct one-byte type tags, so delayed handshake traffic never
//! enters the transport cipher.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use swarm::NodeId;

use crate::Link;

/// The Noise handshake pattern and cryptosystem. `XX` gives mutual authentication
/// of static keys with forward secrecy; the ciphersuite matches the stack's
/// BLAKE-family hashing and a ChaCha20-Poly1305 AEAD.
const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"warren/noise/v1";
const CERT_DOMAIN: &[u8] = b"warren/noise/node-cert/v1";

/// Serialized [`NodeCert`] length: `ed_pub(32) ‖ noise_static_pub(32) ‖ sig(64)`.
const CERT_LEN: usize = 32 + 32 + 64;

/// One-byte type tags prefixing each handshake datagram, so a retransmitted
/// duplicate is recognized and dropped rather than fed to the handshake state
/// machine (reading the wrong message would corrupt it).
const TAG_MSG1: u8 = 1;
const TAG_MSG2: u8 = 2;
const TAG_MSG3: u8 = 3;
const TAG_TRANSPORT: u8 = 4;

/// Bytes of explicit per-datagram nonce prepended to every transport ciphertext.
const NONCE_LEN: usize = 8;
/// ChaCha20-Poly1305 authentication tag length, reserved in every transport datagram.
const TAG_LEN: usize = 16;
const TRANSPORT_OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

const ACK: &[u8] = b"warren-noise-ack-v1";

const REPLAY_WINDOW: usize = 1 << 16;
const REPLAY_WORDS: usize = REPLAY_WINDOW / u64::BITS as usize;

/// Per-handshake-message resend interval and attempt budget over the lossy channel.
const HS_TIMEOUT: Duration = Duration::from_millis(500);
const HS_RETRIES: usize = 10;

/// A peer's identity proof, carried in the Noise handshake payload: its Ed25519
/// public key, the X25519 static it is using for this connection, and a signature
/// binding the two. See the module docs for how it is verified.
struct NodeCert {
    ed_pub: [u8; 32],
    noise_static_pub: [u8; 32],
    sig: [u8; 64],
}

#[derive(Clone, Copy)]
enum Role {
    Initiator = 1,
    Responder = 2,
}

impl NodeCert {
    /// Build our cert: sign the per-connection Noise static with the long-term
    /// Ed25519 identity, so the peer can bind our node id to this Noise session.
    fn create(identity: &crypto::Keypair, noise_static_pub: &[u8], role: Role) -> io::Result<Self> {
        let noise_static_pub: [u8; 32] = noise_static_pub
            .try_into()
            .map_err(|_| bad("noise static key is not 32 bytes"))?;
        let sig = identity
            .sign(&cert_message(role, &noise_static_pub))
            .to_bytes();
        Ok(Self {
            ed_pub: identity.public().to_bytes(),
            noise_static_pub,
            sig,
        })
    }

    fn encode(&self) -> [u8; CERT_LEN] {
        let mut b = [0u8; CERT_LEN];
        b[..32].copy_from_slice(&self.ed_pub);
        b[32..64].copy_from_slice(&self.noise_static_pub);
        b[64..].copy_from_slice(&self.sig);
        b
    }

    fn decode(bytes: &[u8]) -> io::Result<Self> {
        let bytes: [u8; CERT_LEN] = bytes
            .try_into()
            .map_err(|_| bad("node cert has the wrong length"))?;
        Ok(Self {
            ed_pub: bytes[..32].try_into().unwrap(),
            noise_static_pub: bytes[32..64].try_into().unwrap(),
            sig: bytes[64..].try_into().unwrap(),
        })
    }

    /// Verify the cert against the static key Noise authenticated by DH: the signed
    /// static must equal `remote_static`, and the signature must verify under the
    /// claimed Ed25519 key. On success the peer's node id is `hash(ed_pub)`.
    fn verify(&self, remote_static: &[u8], role: Role) -> io::Result<()> {
        if self.noise_static_pub.as_slice() != remote_static {
            return Err(denied(
                "node cert static key does not match the Noise-authenticated key",
            ));
        }
        let pk = crypto::PublicKey::from_bytes(&self.ed_pub)
            .map_err(|_| denied("node cert has an invalid Ed25519 public key"))?;
        pk.verify(
            &cert_message(role, &self.noise_static_pub),
            &crypto::Signature::from_bytes(self.sig),
        )
        .map_err(|_| denied("node cert signature verification failed"))?;
        Ok(())
    }
}

fn cert_message(role: Role, noise_static_pub: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(CERT_DOMAIN.len() + 1 + noise_static_pub.len());
    message.extend_from_slice(CERT_DOMAIN);
    message.push(role as u8);
    message.extend_from_slice(noise_static_pub);
    message
}

/// A punched [`Link`] wrapped in an authenticated, forward-secret Noise session.
/// Generic over the underlying transport `T` so it upgrades either a real
/// [`driver::Channel`] or a test's in-memory link. Construct with [`connect`]
/// (dialer) or [`accept`] (listener); then use it anywhere a [`Link`] is expected.
///
/// [`connect`]: NoiseLink::connect
/// [`accept`]: NoiseLink::accept
pub struct NoiseLink<T: Link> {
    inner: T,
    noise: snow::StatelessTransportState,
    /// Our monotonic send counter — the explicit nonce for each transport datagram.
    send_nonce: AtomicU64,
    recv_replay: Mutex<ReplayWindow>,
    finish_replay: Mutex<Option<FinishReplay>>,
    recv_buf: tokio::sync::Mutex<Box<[u8]>>,
}

struct FinishReplay {
    msg3: Vec<u8>,
    ack: Vec<u8>,
}

struct ReplayWindow {
    highest: Option<u64>,
    bits: Box<[u64]>,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest: None,
            bits: vec![0; REPLAY_WORDS].into_boxed_slice(),
        }
    }

    fn rejects(&self, nonce: u64) -> bool {
        if nonce == u64::MAX {
            return true;
        }
        let Some(highest) = self.highest else {
            return false;
        };
        if nonce > highest {
            return false;
        }
        highest - nonce >= REPLAY_WINDOW as u64 || self.is_set(nonce)
    }

    fn record(&mut self, nonce: u64) {
        if let Some(highest) = self.highest {
            if nonce > highest {
                let advance = nonce - highest;
                if advance >= REPLAY_WINDOW as u64 {
                    self.bits.fill(0);
                } else {
                    for expired in highest + 1..=nonce {
                        self.clear(expired);
                    }
                }
                self.highest = Some(nonce);
            }
        } else {
            self.highest = Some(nonce);
        }
        self.set(nonce);
    }

    fn position(nonce: u64) -> (usize, u32) {
        let bit = nonce as usize % REPLAY_WINDOW;
        (bit / u64::BITS as usize, (bit % u64::BITS as usize) as u32)
    }

    fn is_set(&self, nonce: u64) -> bool {
        let (word, bit) = Self::position(nonce);
        self.bits[word] & (1 << bit) != 0
    }

    fn set(&mut self, nonce: u64) {
        let (word, bit) = Self::position(nonce);
        self.bits[word] |= 1 << bit;
    }

    fn clear(&mut self, nonce: u64) {
        let (word, bit) = Self::position(nonce);
        self.bits[word] &= !(1 << bit);
    }
}

impl<T: Link> NoiseLink<T> {
    /// Dial: run the `XX` handshake as initiator over `inner`, authenticate the
    /// responder, and pin it to `target` (`hash(peer ed_pub) == target`). Returns
    /// [`io::ErrorKind::PermissionDenied`] if the reached peer is not `target`, or a
    /// timeout if the handshake doesn't complete within the retry budget.
    pub async fn connect(
        inner: T,
        identity: &crypto::Keypair,
        target: NodeId,
    ) -> io::Result<NoiseLink<T>> {
        let statik = gen_static()?;
        let mut hs = build(&statik.private, true)?;
        let cert = NodeCert::create(identity, &statik.public, Role::Initiator)?.encode();

        let mut wbuf = [0u8; 2048];
        let mut rbuf = [0u8; 2048];

        // -> e. No payload: XX's message 1 is unencrypted, so sending our cert here
        // would leak the dialer's node id in the clear. Our cert rides the encrypted
        // message 3 instead (the responder reads it from there). Resend until the
        // responder's message 2 arrives.
        let n1 = hs.write_message(&[], &mut wbuf).map_err(noise_err)?;
        let msg1 = tagged(TAG_MSG1, &wbuf[..n1]);
        let peer_cert = 'wait: {
            for _ in 0..HS_RETRIES {
                inner.send(&msg1).await?;
                if let Some(n) = recv_timeout(&inner, &mut rbuf).await? {
                    if n >= 1 && rbuf[0] == TAG_MSG2 {
                        let mut payload = [0u8; 256];
                        let plen = hs
                            .read_message(&rbuf[1..n], &mut payload)
                            .map_err(noise_err)?;
                        break 'wait NodeCert::decode(&payload[..plen])?;
                    }
                }
            }
            return Err(timed_out("Noise handshake: no response (message 2)"));
        };

        // Authenticate and pin the responder before disclosing our identity in message 3.
        // This preserves XX's active identity hiding even if unsigned DHT signaling sends
        // us to the wrong punched endpoint.
        let remote_static = remote_static(&hs)?;
        peer_cert.verify(&remote_static, Role::Responder)?;
        if crypto::hash(&peer_cert.ed_pub) != *target.as_bytes() {
            return Err(denied(
                "Noise handshake: reached peer's identity does not match the dialed node id",
            ));
        }

        // -> s, se (+ our cert). Cache the exact message and retransmit it until the
        // responder confirms handshake completion with an authenticated transport ACK.
        let n3 = hs.write_message(&cert, &mut wbuf).map_err(noise_err)?;
        let msg3 = tagged(TAG_MSG3, &wbuf[..n3]);
        let noise = hs.into_stateless_transport_mode().map_err(noise_err)?;
        let mut recv_replay = ReplayWindow::new();
        let mut acked = false;
        for _ in 0..HS_RETRIES {
            inner.send(&msg3).await?;
            if let Some(n) = recv_timeout(&inner, &mut rbuf).await? {
                if let Some((nonce, payload)) = decrypt_transport(&noise, &rbuf[..n]) {
                    if nonce == 0 && payload == ACK {
                        recv_replay.record(nonce);
                        acked = true;
                        break;
                    }
                }
            }
        }
        if !acked {
            return Err(timed_out("Noise handshake: no completion acknowledgment"));
        }
        let recv_buf = receive_buffer(&inner);
        Ok(NoiseLink {
            inner,
            noise,
            send_nonce: AtomicU64::new(0),
            recv_replay: Mutex::new(recv_replay),
            finish_replay: Mutex::new(None),
            recv_buf,
        })
    }

    /// Accept: run the `XX` handshake as responder over `inner`, authenticate the
    /// initiator, and return the link plus the peer's node id (`hash(peer ed_pub)`).
    pub async fn accept(
        inner: T,
        identity: &crypto::Keypair,
    ) -> io::Result<(NoiseLink<T>, NodeId)> {
        let statik = gen_static()?;
        let mut hs = build(&statik.private, false)?;
        let cert = NodeCert::create(identity, &statik.public, Role::Responder)?.encode();

        let mut wbuf = [0u8; 2048];
        let mut rbuf = [0u8; 2048];

        // <- e. Wait for the initiator's message 1 (we speak second — nothing to
        // resend yet). Message 1 carries no payload (it is unencrypted); the
        // initiator's authenticated cert arrives in the encrypted message 3.
        let mut got_msg1 = false;
        for _ in 0..HS_RETRIES {
            if let Some(n) = recv_timeout(&inner, &mut rbuf).await? {
                if n >= 1 && rbuf[0] == TAG_MSG1 {
                    let mut payload = [0u8; 256];
                    hs.read_message(&rbuf[1..n], &mut payload)
                        .map_err(noise_err)?;
                    got_msg1 = true;
                    break;
                }
            }
        }
        if !got_msg1 {
            return Err(timed_out("Noise handshake: no opener (message 1)"));
        }

        // -> e, ee, s, es (+ our cert). Resend until the initiator's message 3 arrives;
        // a duplicate message 1 means our message 2 was lost, so the loop resends it.
        let n2 = hs.write_message(&cert, &mut wbuf).map_err(noise_err)?;
        let msg2 = tagged(TAG_MSG2, &wbuf[..n2]);
        let (peer_cert, msg3) = 'wait: {
            for _ in 0..HS_RETRIES {
                inner.send(&msg2).await?;
                if let Some(n) = recv_timeout(&inner, &mut rbuf).await? {
                    if n >= 1 && rbuf[0] == TAG_MSG3 {
                        let mut payload = [0u8; 256];
                        let plen = hs
                            .read_message(&rbuf[1..n], &mut payload)
                            .map_err(noise_err)?;
                        break 'wait (NodeCert::decode(&payload[..plen])?, rbuf[..n].to_vec());
                    }
                }
            }
            return Err(timed_out("Noise handshake: no finish (message 3)"));
        };

        let remote_static = remote_static(&hs)?;
        let noise = hs.into_stateless_transport_mode().map_err(noise_err)?;

        peer_cert.verify(&remote_static, Role::Initiator)?;
        let peer_id = NodeId::from_bytes(crypto::hash(&peer_cert.ed_pub));
        let ack = encrypt_transport(&noise, 0, ACK)?;
        inner.send(&ack).await?;
        let recv_buf = receive_buffer(&inner);
        Ok((
            NoiseLink {
                inner,
                noise,
                send_nonce: AtomicU64::new(1),
                recv_replay: Mutex::new(ReplayWindow::new()),
                finish_replay: Mutex::new(Some(FinishReplay { msg3, ack })),
                recv_buf,
            },
            peer_id,
        ))
    }
}

impl<T: Link + Send + Sync> Link for NoiseLink<T> {
    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        if self.inner.max_payload() < TRANSPORT_OVERHEAD || data.len() > self.max_payload() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Noise transport payload exceeds the inner link MTU",
            ));
        }
        let nonce = self
            .send_nonce
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |nonce| {
                nonce.checked_add(1)
            })
            .map_err(|_| bad("Noise transport send nonce exhausted"))?;
        let out = encrypt_transport(&self.noise, nonce, data)?;
        self.inner.send(&out).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut datagram = self.recv_buf.lock().await;
        loop {
            let n = self.inner.recv(&mut datagram).await?;
            let packet = &datagram[..n];

            let finish_ack = self
                .finish_replay
                .lock()
                .expect("finish replay")
                .as_ref()
                .filter(|finish| packet == finish.msg3)
                .map(|finish| finish.ack.clone());
            if let Some(ack) = finish_ack {
                self.inner.send(&ack).await?;
                continue;
            }

            if packet.first() != Some(&TAG_TRANSPORT) || n < TRANSPORT_OVERHEAD {
                continue;
            }
            let nonce = u64::from_le_bytes(
                packet[1..1 + NONCE_LEN]
                    .try_into()
                    .expect("nonce length checked"),
            );
            let mut replay = self.recv_replay.lock().expect("replay window");
            if replay.rejects(nonce) {
                continue;
            }
            let Ok(plaintext) = self
                .noise
                .read_message(nonce, &packet[1 + NONCE_LEN..], buf)
            else {
                continue;
            };
            replay.record(nonce);
            drop(replay);
            self.finish_replay.lock().expect("finish replay").take();
            return Ok(plaintext);
        }
    }

    fn max_payload(&self) -> usize {
        self.inner.max_payload().saturating_sub(TRANSPORT_OVERHEAD)
    }

    fn authenticated(&self) -> bool {
        true
    }
}

fn receive_buffer<T: Link>(inner: &T) -> tokio::sync::Mutex<Box<[u8]>> {
    let len = inner.max_payload().max(TRANSPORT_OVERHEAD);
    tokio::sync::Mutex::new(vec![0u8; len].into_boxed_slice())
}

fn encrypt_transport(
    noise: &snow::StatelessTransportState,
    nonce: u64,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; TRANSPORT_OVERHEAD + payload.len()];
    out[0] = TAG_TRANSPORT;
    out[1..1 + NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
    let n = noise
        .write_message(nonce, payload, &mut out[1 + NONCE_LEN..])
        .map_err(noise_err)?;
    out.truncate(1 + NONCE_LEN + n);
    Ok(out)
}

fn decrypt_transport(
    noise: &snow::StatelessTransportState,
    datagram: &[u8],
) -> Option<(u64, Vec<u8>)> {
    if datagram.first() != Some(&TAG_TRANSPORT) || datagram.len() < TRANSPORT_OVERHEAD {
        return None;
    }
    let nonce = u64::from_le_bytes(datagram[1..1 + NONCE_LEN].try_into().ok()?);
    let mut payload = vec![0u8; datagram.len() - TRANSPORT_OVERHEAD];
    let n = noise
        .read_message(nonce, &datagram[1 + NONCE_LEN..], &mut payload)
        .ok()?;
    payload.truncate(n);
    Some((nonce, payload))
}

/// Generate a fresh per-connection X25519 static keypair for the handshake.
fn gen_static() -> io::Result<snow::Keypair> {
    let params = PARAMS.parse().map_err(noise_err)?;
    snow::Builder::new(params)
        .generate_keypair()
        .map_err(noise_err)
}

/// Build the `XX` handshake state with our generated static as the local private key.
fn build(private: &[u8], initiator: bool) -> io::Result<snow::HandshakeState> {
    let params = PARAMS.parse().map_err(noise_err)?;
    let builder = snow::Builder::new(params)
        .local_private_key(private)
        .map_err(noise_err)?
        .prologue(PROLOGUE)
        .map_err(noise_err)?;
    if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(noise_err)
}

/// Copy out the peer's DH-authenticated static key before the handshake is consumed.
fn remote_static(hs: &snow::HandshakeState) -> io::Result<[u8; 32]> {
    hs.get_remote_static()
        .ok_or_else(|| bad("Noise handshake does not expose a remote static key"))?
        .try_into()
        .map_err(|_| bad("Noise remote static key is not 32 bytes"))
}

/// Receive one datagram, or `None` if the resend interval elapses first.
async fn recv_timeout<T: Link>(inner: &T, buf: &mut [u8]) -> io::Result<Option<usize>> {
    match tokio::time::timeout(HS_TIMEOUT, inner.recv(buf)).await {
        Ok(Ok(n)) => Ok(Some(n)),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(None),
    }
}

/// Prefix a handshake message with its one-byte type tag.
fn tagged(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(tag);
    v.extend_from_slice(body);
    v
}

fn noise_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("noise: {e}"))
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn denied(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg)
}

fn timed_out(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_accepts_reordering_once() {
        let mut replay = ReplayWindow::new();
        for nonce in [10, 8, 9, 12, 11] {
            assert!(!replay.rejects(nonce));
            replay.record(nonce);
            assert!(replay.rejects(nonce));
        }
    }

    #[test]
    fn replay_window_expires_only_packets_outside_the_window() {
        let mut replay = ReplayWindow::new();
        replay.record(0);
        replay.record(REPLAY_WINDOW as u64);

        assert!(replay.rejects(0));
        assert!(!replay.rejects(1));
        replay.record(1);
        assert!(replay.rejects(1));
    }
}
