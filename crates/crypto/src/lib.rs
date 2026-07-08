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
