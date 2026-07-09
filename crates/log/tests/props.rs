//! Property tests for the signed append-only log: proofs verify for every block
//! of any log, tampering always fails, and the wire codec is panic-free and
//! round-trips.

use crypto::Keypair;
use log::{verify_block, verify_head, Head, Log, Proof};
use proptest::prelude::*;

/// A log built from an arbitrary, non-empty sequence of blocks.
fn arb_blocks() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..48), 1..40)
}

fn build(blocks: &[Vec<u8>]) -> Log {
    let mut log = Log::new(Keypair::from_seed(&[3u8; 32]));
    for b in blocks {
        log.append(b.clone());
    }
    log
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Every block of any log verifies against the signed head with its proof.
    #[test]
    fn every_block_verifies(blocks in arb_blocks()) {
        let log = build(&blocks);
        let pk = log.public_key();
        let head = log.head();
        prop_assert!(verify_head(&pk, &head));
        prop_assert_eq!(head.len as usize, blocks.len());
        for (i, block) in blocks.iter().enumerate() {
            let proof = log.proof(i).unwrap();
            prop_assert!(verify_block(&pk, &head, i as u64, block, &proof));
        }
    }

    /// Flipping any bit of a block makes its proof fail (unless the flip is a
    /// no-op, i.e. the byte is unchanged — excluded by construction).
    #[test]
    fn tampered_block_fails(blocks in arb_blocks(), seed in any::<u64>()) {
        let log = build(&blocks);
        let pk = log.public_key();
        let head = log.head();
        let i = (seed as usize) % blocks.len();
        let mut block = blocks[i].clone();
        // Perturb: flip a bit of an existing byte, or append one if empty.
        if let Some(b) = block.first_mut() {
            *b ^= 1;
        } else {
            block.push(0);
        }
        let proof = log.proof(i).unwrap();
        prop_assert!(!verify_block(&pk, &head, i as u64, &block, &proof));
    }

    /// Block `i`'s proof, presented for a *different* index `j`, is rejected —
    /// provided the two blocks differ. (A Merkle inclusion proof attests
    /// membership, not a unique position: identical block bytes have identical
    /// leaves and can legitimately cross-verify in some tree shapes, so the
    /// honest guarantee is only for distinct-content blocks. Distinct *content*
    /// at a wrong index is what a verifier actually relies on.)
    #[test]
    fn distinct_block_does_not_cross_verify_at_another_index(
        blocks in arb_blocks(),
        seed in any::<u64>(),
    ) {
        prop_assume!(blocks.len() >= 2);
        let log = build(&blocks);
        let pk = log.public_key();
        let head = log.head();
        let i = (seed as usize) % blocks.len();
        let j = (i + 1) % blocks.len(); // a different index
        let proof = log.proof(i).unwrap();
        prop_assume!(blocks[i] != blocks[j]);
        prop_assert!(!verify_block(&pk, &head, j as u64, &blocks[i], &proof));
    }

    /// Decoding arbitrary bytes never panics.
    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = Head::decode(&bytes);
        let _ = Proof::decode(&bytes);
    }

    /// Head and every proof round-trip through their codec.
    #[test]
    fn codec_roundtrips(blocks in arb_blocks()) {
        let log = build(&blocks);
        let head = log.head();
        prop_assert_eq!(Head::decode(&head.encode()).unwrap(), head);
        for i in 0..blocks.len() {
            let proof = log.proof(i).unwrap();
            prop_assert_eq!(Proof::decode(&proof.encode()).unwrap(), proof);
        }
    }
}
