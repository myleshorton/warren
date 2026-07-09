//! Property tests for the content-addressed blob store: split→store→reassemble
//! round-trips for any data and chunk size, content addressing is self-verifying
//! and tamper-evident, and the manifest codec is panic-free and round-trips.

use blob::{split_with, verify_chunk, Manifest, Store};
use proptest::prelude::*;

proptest! {
    /// Any data, split at any chunk size, stored and reassembled, is unchanged.
    #[test]
    fn split_store_reassemble_roundtrips(
        data in prop::collection::vec(any::<u8>(), 0..5000),
        chunk_size in 1usize..=512,
    ) {
        let (manifest, chunks) = split_with(&data, chunk_size);
        prop_assert_eq!(manifest.total_len, data.len() as u64);
        prop_assert_eq!(manifest.chunks.len(), chunks.len());

        let mut store = Store::new();
        for chunk in &chunks {
            store.put(chunk.clone());
        }
        let got = store.reassemble(&manifest);
        prop_assert_eq!(got.as_deref(), Some(data.as_slice()));
    }

    /// Every chunk verifies against its own manifest hash, and any different
    /// bytes fail — content addressing is self-verifying.
    #[test]
    fn chunks_are_self_verifying(
        data in prop::collection::vec(any::<u8>(), 1..3000),
        chunk_size in 1usize..=256,
    ) {
        let (manifest, chunks) = split_with(&data, chunk_size);
        for (h, chunk) in manifest.chunks.iter().zip(&chunks) {
            prop_assert!(verify_chunk(h, chunk));
            // A perturbed chunk no longer matches its hash.
            let mut bad = chunk.clone();
            bad.push(0);
            prop_assert!(!verify_chunk(h, &bad));
        }
    }

    /// The manifest id changes whenever the chunk list or total length changes,
    /// and is stable otherwise.
    #[test]
    fn manifest_id_is_a_content_address(
        a in prop::collection::vec(any::<u8>(), 0..3000),
        b in prop::collection::vec(any::<u8>(), 0..3000),
    ) {
        let ma = split_with(&a, 128).0;
        prop_assert_eq!(ma.id(), split_with(&a, 128).0.id()); // stable
        let mb = split_with(&b, 128).0;
        // Different content (thus a different chunk list or length) → different id.
        if a != b {
            prop_assert_ne!(ma.id(), mb.id());
        }
    }

    /// Decoding arbitrary bytes never panics.
    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = Manifest::decode(&bytes);
    }

    /// A manifest round-trips through its codec.
    #[test]
    fn manifest_codec_roundtrips(
        data in prop::collection::vec(any::<u8>(), 0..5000),
        chunk_size in 1usize..=512,
    ) {
        let manifest = split_with(&data, chunk_size).0;
        prop_assert_eq!(Manifest::decode(&manifest.encode()).unwrap(), manifest);
    }
}
