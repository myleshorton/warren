//! Property tests: identity and signature invariants across randomized inputs.

use crypto::{Keypair, PublicKey};
use proptest::prelude::*;

proptest! {
    /// Any seed produces a usable identity whose signatures verify.
    #[test]
    fn any_seed_signs_and_verifies(seed: [u8; 32], message: Vec<u8>) {
        let kp = Keypair::from_seed(&seed);
        let sig = kp.sign(&message);
        prop_assert!(kp.public().verify(&message, &sig).is_ok());
    }

    /// The same seed always yields the same identity (deterministic derivation).
    #[test]
    fn seed_derivation_is_deterministic(seed: [u8; 32]) {
        let a = Keypair::from_seed(&seed);
        let b = Keypair::from_seed(&seed);
        prop_assert_eq!(a.public(), b.public());
        prop_assert_eq!(a.seed(), b.seed());
    }

    /// A signature over one message never verifies against a different message.
    #[test]
    fn signatures_are_message_bound(seed: [u8; 32], m1: Vec<u8>, m2: Vec<u8>) {
        prop_assume!(m1 != m2);
        let kp = Keypair::from_seed(&seed);
        let sig = kp.sign(&m1);
        prop_assert!(kp.public().verify(&m2, &sig).is_err());
    }

    /// Flipping any bit of a valid signature breaks verification.
    #[test]
    fn tampered_signature_fails(seed: [u8; 32], message: Vec<u8>, bit in 0usize..512) {
        let kp = Keypair::from_seed(&seed);
        let mut raw = kp.sign(&message).to_bytes();
        raw[bit / 8] ^= 1 << (bit % 8);
        let tampered = crypto::Signature::from_bytes(raw);
        prop_assert!(kp.public().verify(&message, &tampered).is_err());
    }

    /// Distinct seeds give distinct public keys (no accidental collisions).
    #[test]
    fn distinct_seeds_distinct_keys(a: [u8; 32], b: [u8; 32]) {
        prop_assume!(a != b);
        prop_assert_ne!(
            Keypair::from_seed(&a).public(),
            Keypair::from_seed(&b).public()
        );
    }

    /// Discovery keys are a stable function of the public key and never equal
    /// the key itself.
    #[test]
    fn discovery_key_stable(seed: [u8; 32]) {
        let pk = Keypair::from_seed(&seed).public();
        prop_assert_eq!(pk.discovery_key(), pk.discovery_key());
        prop_assert_ne!(pk.discovery_key(), pk.to_bytes());
    }

    /// Parsing arbitrary 32-byte inputs as public keys never panics.
    #[test]
    fn public_key_parse_never_panics(bytes: [u8; 32]) {
        let _ = PublicKey::from_bytes(&bytes);
    }

    /// A blinded topic is a stable function of (key, epoch), rotates with the
    /// epoch, and is never the cleartext key — for any key and any two distinct
    /// epochs.
    #[test]
    fn blinded_topic_stable_and_rotates(seed: [u8; 32], e1: u64, e2: u64) {
        prop_assume!(e1 != e2);
        let pk = Keypair::from_seed(&seed).public();
        prop_assert_eq!(pk.blinded_topic(e1), pk.blinded_topic(e1));
        prop_assert_ne!(pk.blinded_topic(e1), pk.blinded_topic(e2));
        prop_assert_ne!(pk.blinded_topic(e1), pk.to_bytes());
    }

    /// `epoch` is monotone non-decreasing in time and never panics (including a
    /// zero length), and is constant within a window of `epoch_len` seconds.
    #[test]
    fn epoch_is_monotone_and_total(now: u64, len: u64) {
        let e = crypto::epoch(now, len);
        prop_assert!(crypto::epoch(now.saturating_add(1), len) >= e);
        // Within the same window, the epoch does not change.
        let step = len.max(1);
        let window_start = (now / step) * step;
        prop_assert_eq!(crypto::epoch(window_start, len), e);
    }
}
