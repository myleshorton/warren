//! Soak: a windowed seeder's disk stays **bounded by its window** no matter how far the
//! author's feed grows. This drives the feed-level operation `Session::run_mirror_window`
//! performs each growth round — rebuild the sparse replica for the current window, then
//! prune the prefix that fell out — over many rounds, and asserts the store never holds more
//! than the window's worth of blocks (nor an unbounded number of tree nodes). RAM is already
//! O(log n) per feed by construction (the accumulator keeps only peaks; no leaf vectors), so
//! the on-disk bound is the property left to demonstrate.

use std::sync::Arc;

use crypto::Keypair;
use feed::{FeedStore, Log, MemStore, Replica};

#[test]
fn a_windowed_seeder_stays_disk_bounded_as_the_author_grows() {
    let window = 10u64;
    let step = 7u64; // grow by less than the window, so windows overlap round to round

    // The author holds the whole feed; the seeder mirrors only a moving window into `store`.
    let mut author = Log::new(Keypair::from_seed(&[0x9c; 32]));
    let pk = author.public_key();
    let feed = pk.to_bytes();
    let store: Arc<dyn FeedStore> = Arc::new(MemStore::new());

    for _round in 0..30 {
        // The author appends `step` more blocks.
        for _ in 0..step {
            let i = author.len();
            author.append(vec![i as u8; 4]);
        }
        let len = author.len() as u64;
        let start = len.saturating_sub(window);

        // Refresh the window exactly as run_mirror_window does: a fresh sparse replica for
        // the current head + peaks, ingest the last `window` blocks, then prune the rest.
        let mut mirror = Replica::sparse(pk, author.head(), author.peak_nodes(), store.clone())
            .expect("peaks reproduce the head root");
        for i in start..len {
            let proof = author.proof(i as usize).unwrap();
            assert!(
                mirror.ingest(i, author.get(i as usize).unwrap(), &proof),
                "window block {i} ingests"
            );
        }
        mirror.prune(start);

        // The mirror holds exactly the window, and every held block matches the author.
        assert_eq!(
            mirror.held_ranges(),
            vec![(start, len)],
            "held window slides with the author (len {len})"
        );
        for i in start..len {
            assert_eq!(mirror.block(i as usize), author.get(i as usize));
        }

        // Disk is bounded: the store holds only the window's blocks, never the whole feed.
        let stored_blocks = (0..len)
            .filter(|&i| store.has_block(&feed, i).unwrap())
            .count() as u64;
        assert_eq!(
            stored_blocks,
            window.min(len),
            "seeder holds only the window ({window}), not the full {len}-block feed"
        );

        // Tree nodes are bounded too — peaks + the window's audit paths, which grows only
        // logarithmically with the length, never linearly. (A full {len}-leaf tree would
        // have ~2·len nodes; the seeder keeps a small, length-independent cap.)
        let stored_nodes = (0..2 * len)
            .filter(|&idx| store.node(&feed, idx).unwrap().is_some())
            .count() as u64;
        assert!(
            stored_nodes <= 4 * window + 70,
            "node set stays bounded ({stored_nodes}) as the feed grows to {len}"
        );
    }

    // After all that growth the author is well past the window…
    assert!(author.len() as u64 >= 200);
    // …yet the seeder's final footprint is still just the window.
    let final_len = author.len() as u64;
    let held = (0..final_len)
        .filter(|&i| store.has_block(&feed, i).unwrap())
        .count() as u64;
    assert_eq!(held, window, "final on-disk block count equals the window");
}
