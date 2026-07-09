//! Identity and hashing primitives for the stack.
//!
//! - **Signing**: Ed25519 (RFC 8032) via `ed25519-dalek`. A [`Keypair`] is an
//!   author/channel/node identity; a [`PublicKey`] names it.
//! - **Hashing**: BLAKE3 via [`hash`]. Content addressing and merkle trees use
//!   this; the choice of BLAKE3 (over Hypercore's BLAKE2b) is what buys verified
//!   *byte-range* streaming later — see the design doc.
//! - **Discovery keys**: [`PublicKey::discovery_key`] derives a topic id that can
//!   be announced/looked up without granting the capability to read the data it
//!   names — the same separation Hypercore draws between a key and its
//!   discovery key.
//! - **Blinded, rotating topics**: [`PublicKey::blinded_topic`] derives a
//!   *time-rotating* topic — conceptually `H(key ‖ epoch)`, concretely a keyed
//!   BLAKE3 hash (see the method for the exact, KAT-pinned construction) — so a
//!   DHT crawler who does not hold the specific key sees only opaque ids that
//!   change each [`epoch`] — it cannot catalogue the network or keep a static
//!   blocklist. (It does *not* hide the topic from a censor who already has the
//!   key; that is what the PSK variant, [`PublicKey::blinded_topic_psk`], is for.)
//!
//! This crate is pure (no I/O) so it can be property- and known-answer-tested
//! exhaustively.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

/// Length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of the secret seed a [`Keypair`] is derived from, in bytes.
pub const SEED_LEN: usize = 32;
/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;
/// Length of a BLAKE3 hash, in bytes.
pub const HASH_LEN: usize = 32;

/// A 32-byte BLAKE3 digest.
pub type Hash = [u8; HASH_LEN];

/// Domain separator so discovery keys can never collide with any other keyed
/// hash we compute from a public key.
const DISCOVERY_DOMAIN: &[u8] = b"holepunch:discovery-key:v1";

/// Domain separator for key-blinded rotating topics, distinct from
/// [`DISCOVERY_DOMAIN`] so a blinded topic can never collide with a discovery
/// key even at the same (implicit) epoch.
const BLINDED_TOPIC_DOMAIN: &[u8] = b"holepunch:blinded-topic:v1";

/// BLAKE3 `derive_key` context for turning an arbitrary-length pre-shared key
/// into the 32-byte key used by the PSK-blinded topic. A context string is the
/// KDF's domain separator.
const BLINDED_TOPIC_PSK_CONTEXT: &str = "holepunch:blinded-topic-psk:v1";

/// Errors from parsing or verifying key material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Public key bytes were not a valid Ed25519 point.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Signature verification failed for this message and key.
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Hash arbitrary data with BLAKE3.
pub fn hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Hash the concatenation of `parts` with BLAKE3, without allocating to join
/// them. `hash_parts(&[a, b])` equals `hash(&[a, b].concat())` but streams each
/// part into the hasher — useful for a domain tag followed by a large payload
/// (e.g. a Merkle leaf `tag ‖ block`) where copying the payload would be waste.
pub fn hash_parts(parts: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// The current epoch for time-synchronized topic rotation: `⌊now / epoch_len⌋`,
/// both in whole seconds. Participants with roughly synchronized clocks compute
/// the *same* epoch, so a rotating topic's provider set does not fragment. The
/// caller owns the clock (this crate is pure). A zero `epoch_len_secs` is a
/// misuse; rather than divide by zero it is clamped to one second.
///
/// Shorter epochs tighten the correlation window a crawler gets but add
/// re-announce churn; longer epochs do the reverse. Epoch boundaries are covered
/// by *overlap* at the I/O layer (announce the current and next epoch, look up
/// the current and previous), so clock skew never opens an availability gap.
pub fn epoch(now_secs: u64, epoch_len_secs: u64) -> u64 {
    now_secs / epoch_len_secs.max(1)
}

/// An Ed25519 signing identity (secret seed + derived public key).
///
/// Cloneable but never printed: its `Debug` redacts the secret.
#[derive(Clone)]
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Generate a new random identity from the operating system CSPRNG.
    ///
    /// Panics only if the OS entropy source fails, which is unrecoverable.
    pub fn generate() -> Self {
        let mut seed = [0u8; SEED_LEN];
        getrandom::getrandom(&mut seed).expect("OS entropy source unavailable");
        Self::from_seed(&seed)
    }

    /// Derive an identity deterministically from a 32-byte seed.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte secret seed. Handle with care.
    pub fn seed(&self) -> [u8; SEED_LEN] {
        self.signing.to_bytes()
    }

    /// The public key naming this identity.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key())
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.signing.sign(message).to_bytes())
    }
}

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public())
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// An Ed25519 public key — a stable, shareable identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Parse a public key from its 32-byte encoding.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(bytes)
            .map(PublicKey)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// The 32-byte encoding of this key.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Borrow the 32-byte encoding without copying.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        self.0.as_bytes()
    }

    /// Verify a signature over `message` by this key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.0
            .verify(message, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// Derive the discovery key: a topic id announceable without conferring the
    /// ability to read whatever this key protects.
    ///
    /// Defined as a keyed BLAKE3 hash with this public key as the key over a
    /// fixed domain separator, so it is a deterministic, one-way function of the
    /// public key.
    pub fn discovery_key(&self) -> Hash {
        *blake3::keyed_hash(self.as_bytes(), DISCOVERY_DOMAIN).as_bytes()
    }

    /// Derive a **key-blinded, rotating topic** for the given [`epoch`]:
    /// conceptually `H(key ‖ epoch)`. Concretely — and this is what the KAT pins,
    /// so a reimplementation must match it byte for byte — a keyed BLAKE3 hash
    /// with this public key as the key, over
    /// `BLINDED_TOPIC_DOMAIN ‖ epoch.to_le_bytes()`.
    ///
    /// Any viewer who knows this key (as they must, to verify the content) can
    /// compute the same topic and so discover providers. A DHT crawler who does
    /// *not* hold this specific key sees only an opaque id that changes every
    /// epoch: it cannot map the topic back to the content, cannot cheaply
    /// catalogue the network, and cannot keep a precomputed blocklist current.
    ///
    /// This does not hide the topic from a censor who *does* hold the key — they
    /// recompute it just as a viewer does. For that, use [`Self::blinded_topic_psk`].
    pub fn blinded_topic(&self, epoch: u64) -> Hash {
        let mut hasher = blake3::Hasher::new_keyed(self.as_bytes());
        hasher.update(BLINDED_TOPIC_DOMAIN);
        hasher.update(&epoch.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Derive a **PSK-blinded, rotating topic** for the given [`epoch`]:
    /// conceptually `H_psk(key ‖ epoch)`, keyed by a pre-shared key rather than
    /// the (often public) content key. Concretely: a keyed BLAKE3 hash whose key
    /// is `blake3::derive_key(BLINDED_TOPIC_PSK_CONTEXT, psk)` (so a `psk` of any
    /// length is accepted), over `key.as_bytes() ‖ epoch.to_le_bytes()`. This is
    /// BLAKE3 throughout, not HMAC.
    ///
    /// Only holders of the PSK can compute the topic, so even a censor who knows
    /// the content key but not the PSK is blind. The cost is distributing the
    /// PSK out of band; use it for private channels where that is acceptable.
    pub fn blinded_topic_psk(&self, psk: &[u8], epoch: u64) -> Hash {
        let key = blake3::derive_key(BLINDED_TOPIC_PSK_CONTEXT, psk);
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(self.as_bytes());
        hasher.update(&epoch.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Public keys are safe to print; show a short hex prefix for logs.
        let b = self.to_bytes();
        write!(
            f,
            "PublicKey({:02x}{:02x}{:02x}{:02x}…)",
            b[0], b[1], b[2], b[3]
        )
    }
}

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wrap raw signature bytes.
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw signature bytes.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Signature({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032, Test 1: seed -> public key derivation. This pins our identity
    // scheme to the standard; a wrong derivation fails here immediately.
    #[test]
    fn ed25519_rfc8032_public_key_vector() {
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let seed: [u8; 32] = seed.try_into().unwrap();
        let kp = Keypair::from_seed(&seed);
        assert_eq!(
            hex::encode(kp.public().to_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    // hash_parts streams the parts but must equal hashing their concatenation.
    #[test]
    fn hash_parts_equals_hash_of_concatenation() {
        let a = b"warren-log-head\x00";
        let b = vec![0x5au8; 4096];
        assert_eq!(hash_parts(&[a, &b]), hash(&[a.as_slice(), &b].concat()));
        assert_eq!(hash_parts(&[]), hash(b""));
        assert_eq!(hash_parts(&[b"", b"x", b""]), hash(b"x"));
    }

    // BLAKE3 known answer for the empty input.
    #[test]
    fn blake3_empty_input_vector() {
        assert_eq!(
            hex::encode(hash(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate();
        let msg = b"the network is the infrastructure";
        let sig = kp.sign(msg);
        assert!(kp.public().verify(msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"original");
        assert_eq!(
            kp.public().verify(b"tampered", &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn verify_rejects_other_signer() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let msg = b"whose signature is this";
        let sig = a.sign(msg);
        assert_eq!(
            b.public().verify(msg, &sig),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn discovery_key_is_deterministic_and_distinct_from_key() {
        let kp = Keypair::generate();
        let pk = kp.public();
        assert_eq!(pk.discovery_key(), pk.discovery_key());
        assert_ne!(pk.discovery_key(), pk.to_bytes());
    }

    #[test]
    fn epoch_is_floor_division_and_never_divides_by_zero() {
        assert_eq!(epoch(0, 3600), 0);
        assert_eq!(epoch(3599, 3600), 0);
        assert_eq!(epoch(3600, 3600), 1);
        assert_eq!(epoch(7201, 3600), 2);
        // A zero length is a misuse; it must not panic (treated as 1s).
        assert_eq!(epoch(42, 0), 42);
    }

    #[test]
    fn blinded_topic_is_deterministic_rotates_and_is_opaque() {
        let pk = Keypair::from_seed(&[9u8; 32]).public();
        // Deterministic within an epoch — so every participant computes the same
        // topic and the provider set does not fragment.
        assert_eq!(pk.blinded_topic(100), pk.blinded_topic(100));
        // Rotates: a different epoch yields an unrelated topic, so a crawler's
        // catalogue of this epoch's topic is stale next epoch.
        assert_ne!(pk.blinded_topic(100), pk.blinded_topic(101));
        // Opaque: not the cleartext key, and distinct from the static discovery key.
        assert_ne!(pk.blinded_topic(100), pk.to_bytes());
        assert_ne!(pk.blinded_topic(100), pk.discovery_key());
    }

    #[test]
    fn blinded_topic_is_key_specific() {
        // Two different feeds produce different topics in the same epoch, so a
        // topic reveals nothing about another feed and can't be found without the
        // specific key.
        let a = Keypair::from_seed(&[1u8; 32]).public();
        let b = Keypair::from_seed(&[2u8; 32]).public();
        assert_ne!(a.blinded_topic(100), b.blinded_topic(100));
    }

    // Pin the wire construction (domain tag ‖ little-endian epoch, keyed by the
    // public key). If the format ever changes, participants on different versions
    // would compute different topics and silently fail to rendezvous — this KAT
    // turns that into a test failure.
    #[test]
    fn blinded_topic_matches_its_documented_construction() {
        let pk = Keypair::from_seed(&[9u8; 32]).public();
        let mut hasher = blake3::Hasher::new_keyed(pk.as_bytes());
        hasher.update(b"holepunch:blinded-topic:v1");
        hasher.update(&7u64.to_le_bytes());
        assert_eq!(pk.blinded_topic(7), *hasher.finalize().as_bytes());
    }

    // Pin the PSK-blinded construction too: the 32-byte hash key is
    // `derive_key(context, psk)`, and the data hashed is `public key ‖ le(epoch)`.
    // Interop across implementations depends on every one of these bytes.
    #[test]
    fn psk_blinded_topic_matches_its_documented_construction() {
        let pk = Keypair::from_seed(&[9u8; 32]).public();
        let key = blake3::derive_key("holepunch:blinded-topic-psk:v1", b"secret");
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(pk.as_bytes());
        hasher.update(&7u64.to_le_bytes());
        assert_eq!(
            pk.blinded_topic_psk(b"secret", 7),
            *hasher.finalize().as_bytes()
        );
    }

    #[test]
    fn psk_blinded_topic_depends_on_psk_and_differs_from_key_blinded() {
        let pk = Keypair::from_seed(&[9u8; 32]).public();
        // Deterministic and rotates, like the key-blinded variant.
        assert_eq!(
            pk.blinded_topic_psk(b"secret", 5),
            pk.blinded_topic_psk(b"secret", 5)
        );
        assert_ne!(
            pk.blinded_topic_psk(b"secret", 5),
            pk.blinded_topic_psk(b"secret", 6)
        );
        // A different PSK yields a different topic — a key-holding censor without
        // the PSK cannot derive it.
        assert_ne!(
            pk.blinded_topic_psk(b"secret", 5),
            pk.blinded_topic_psk(b"other", 5)
        );
        // And it is not the key-blinded topic (different keying regime).
        assert_ne!(pk.blinded_topic_psk(b"secret", 5), pk.blinded_topic(5));
    }

    #[test]
    fn debug_keypair_never_leaks_seed() {
        let kp = Keypair::from_seed(&[7u8; 32]);
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("redacted"));
        // The seed's hex must not appear anywhere in the debug output.
        assert!(!dbg.contains(&hex::encode([7u8; 32])));
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let pk = Keypair::generate().public();
        let parsed = PublicKey::from_bytes(&pk.to_bytes()).unwrap();
        assert_eq!(pk, parsed);
    }
}
