//! Content-encryption envelope — a **policy-free** confidentiality primitive.
//!
//! This provides the *mechanism* ("how to encrypt"); it deliberately says nothing
//! about *who* may decrypt — key management (deriving keys from a channel secret,
//! per-recipient wrapping, where a wrapped key travels) is the application's trust
//! model and lives in the app. An app that hands the transport ciphertext gets
//! blind relays/mirrors for free, since the rest of the stack moves opaque bytes.
//!
//! The content cipher is an **unauthenticated** seekable stream cipher
//! (XChaCha20). Integrity is expected to come from content-addressing the
//! ciphertext and signing that address out of band (as `feed`/`blob` already do);
//! keeping the cipher seekable is what preserves progressive/byte-range streaming.
//! AEAD (XChaCha20-Poly1305) is used only for the small key-wrap, which has no
//! signed hash to lean on.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::XChaCha20;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::hash_parts;

/// Length of a content key, in bytes.
pub const CONTENT_KEY_LEN: usize = 32;
/// Length of a nonce (XChaCha20 / XChaCha20-Poly1305), in bytes.
pub const NONCE_LEN: usize = 24;

/// Derive a 32-byte key from a secret and a domain label (BLAKE3 of
/// `domain ‖ secret`). Always domain-separate distinct uses of a shared secret.
/// Suitable when `secret` is high-entropy; a low-entropy secret wants a slow KDF.
pub fn derive_key(secret: &[u8], domain: &[u8]) -> [u8; CONTENT_KEY_LEN] {
    hash_parts(&[domain, secret])
}

fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS RNG unavailable");
}

/// A freshly sealed payload: the ciphertext plus the random key and nonce used to
/// produce it (which the caller wraps + records however its trust model dictates).
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub key: [u8; CONTENT_KEY_LEN],
    pub nonce: [u8; NONCE_LEN],
}

/// Encrypt `plaintext` under a fresh random content key + nonce.
pub fn seal(plaintext: &[u8]) -> Sealed {
    let mut key = [0u8; CONTENT_KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut key);
    fill_random(&mut nonce);
    let mut ciphertext = plaintext.to_vec();
    xor_keystream(&key, &nonce, 0, &mut ciphertext);
    Sealed {
        ciphertext,
        key,
        nonce,
    }
}

/// XOR `data` — which begins at byte `offset` within the stream — with the
/// XChaCha20 keystream. Encryption and decryption are the same operation; the
/// `offset` makes it **seekable**, so a prefix (or any range) can be decrypted
/// progressively as bytes arrive.
pub fn xor_keystream(
    key: &[u8; CONTENT_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    offset: u64,
    data: &mut [u8],
) {
    let mut cipher = XChaCha20::new_from_slices(key, nonce).expect("32-byte key + 24-byte nonce");
    cipher.seek(offset);
    cipher.apply_keystream(data);
}

/// Decrypt a whole ciphertext (equivalently, `xor_keystream` from offset 0).
pub fn open(key: &[u8; CONTENT_KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = ciphertext.to_vec();
    xor_keystream(key, nonce, 0, &mut out);
    out
}

/// Wrap (encrypt + authenticate) a content key under a key-encryption-key.
/// Returns the nonce and the wrapped bytes; both go wherever the app records keys.
pub fn wrap_key(kek: &[u8; 32], key: &[u8; CONTENT_KEY_LEN]) -> ([u8; NONCE_LEN], Vec<u8>) {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(kek).expect("32-byte key");
    let wrapped = cipher
        .encrypt(XNonce::from_slice(&nonce), key.as_slice())
        .expect("AEAD encrypt");
    (nonce, wrapped)
}

/// Recover a content key wrapped by [`wrap_key`]. `None` if the key-encryption-key
/// is wrong or the wrapped bytes were tampered with.
pub fn unwrap_key(
    kek: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    wrapped: &[u8],
) -> Option<[u8; CONTENT_KEY_LEN]> {
    let cipher = XChaCha20Poly1305::new_from_slice(kek).ok()?;
    let plain = cipher.decrypt(XNonce::from_slice(nonce), wrapped).ok()?;
    plain.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips() {
        let msg = b"the quick brown fox jumps over the lazy dog".repeat(1000);
        let s = seal(&msg);
        assert_ne!(s.ciphertext, msg, "ciphertext differs from plaintext");
        assert_eq!(open(&s.key, &s.nonce, &s.ciphertext), msg);
    }

    #[test]
    fn seekable_decrypt_matches_a_suffix() {
        let msg: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let s = seal(&msg);
        // Decrypt only the range [1234, 5000) using the offset — progressive path.
        let off = 1234usize;
        let mut chunk = s.ciphertext[off..].to_vec();
        xor_keystream(&s.key, &s.nonce, off as u64, &mut chunk);
        assert_eq!(chunk, &msg[off..]);
    }

    #[test]
    fn key_wrap_round_trips_and_rejects_wrong_kek() {
        let kek = derive_key(b"high-entropy-channel-secret", b"murmur:content-kek:v1");
        let s = seal(b"hello");
        let (n, wrapped) = wrap_key(&kek, &s.key);
        assert_eq!(unwrap_key(&kek, &n, &wrapped), Some(s.key));

        let wrong = derive_key(b"different-secret", b"murmur:content-kek:v1");
        assert_eq!(unwrap_key(&wrong, &n, &wrapped), None, "wrong KEK fails");
    }

    #[test]
    fn derive_key_is_domain_separated() {
        let secret = b"same-secret";
        assert_ne!(
            derive_key(secret, b"domain-a"),
            derive_key(secret, b"domain-b"),
            "different domains yield independent keys"
        );
    }

    #[test]
    fn a_censor_cannot_predict_the_ciphertext_of_a_known_plaintext() {
        // Two seals of identical plaintext differ (random keys) → content-address
        // over ciphertext is unpredictable from the plaintext alone.
        let msg = b"a banned clip";
        assert_ne!(seal(msg).ciphertext, seal(msg).ciphertext);
    }
}
