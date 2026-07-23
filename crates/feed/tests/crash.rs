//! Crash injection: a [`FeedStore`] whose `commit` can be made to fail at will, proving the
//! substrate's **commit-before-mutate** invariant. `Log::try_append`, `Replica::advance`,
//! and `Replica::ingest` all persist to the store *before* touching in-RAM state, so a
//! failed commit must leave the log/replica exactly as it was — no torn append, no
//! half-ingested block, no accumulator running ahead of the store — and the feed stays
//! consistent (and provable) once the store recovers.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crypto::{Hash, Keypair};
use feed::{
    verify_block, Batch, FeedKey, FeedStore, Head, Log, MemStore, Replica, Source, StoreError,
    StoreResult,
};

/// Wraps a real [`MemStore`]; while `armed`, its next `commit` fails with a backend error.
/// Every read still works, so the test observes the pre-commit state directly.
struct CrashStore {
    inner: MemStore,
    armed: AtomicBool,
}

impl CrashStore {
    fn new() -> Self {
        Self {
            inner: MemStore::new(),
            armed: AtomicBool::new(false),
        }
    }
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }
}

impl FeedStore for CrashStore {
    fn commit(&self, feed: &FeedKey, batch: Batch) -> StoreResult<()> {
        if self.armed.load(Ordering::SeqCst) {
            return Err(StoreError::Backend("injected commit failure".into()));
        }
        self.inner.commit(feed, batch)
    }
    fn prune(
        &self,
        feed: &FeedKey,
        retain_from: u64,
        retain_nodes: &BTreeSet<u64>,
    ) -> StoreResult<()> {
        self.inner.prune(feed, retain_from, retain_nodes)
    }
    fn block(&self, feed: &FeedKey, index: u64) -> StoreResult<Option<Vec<u8>>> {
        self.inner.block(feed, index)
    }
    fn node(&self, feed: &FeedKey, index: u64) -> StoreResult<Option<Hash>> {
        self.inner.node(feed, index)
    }
    fn head(&self, feed: &FeedKey) -> StoreResult<Option<Head>> {
        self.inner.head(feed)
    }
    fn has_block(&self, feed: &FeedKey, index: u64) -> StoreResult<bool> {
        self.inner.has_block(feed, index)
    }
    fn contiguous_len(&self, feed: &FeedKey) -> StoreResult<u64> {
        self.inner.contiguous_len(feed)
    }
    fn feeds(&self) -> StoreResult<Vec<FeedKey>> {
        self.inner.feeds()
    }
}

#[test]
fn a_failed_append_leaves_the_log_unchanged() {
    let store = Arc::new(CrashStore::new());
    let mut log = Log::with_store(
        Keypair::from_seed(&[1; 32]),
        store.clone() as Arc<dyn FeedStore>,
    )
    .unwrap();
    for i in 0..5u8 {
        log.append(vec![i; i as usize + 1]);
    }
    let head_before = log.head();
    let len_before = log.len();

    // Arm the store so the next append's commit fails.
    store.arm();
    assert!(
        log.try_append(vec![99; 3]).is_err(),
        "the append surfaces the store failure"
    );
    // Commit-before-mutate: the log is exactly as it was — no torn append.
    assert_eq!(
        log.len(),
        len_before,
        "length unchanged after a failed append"
    );
    assert_eq!(log.head(), head_before, "head unchanged");
    assert_eq!(log.get(5), None, "the failed block was never added");

    // Recover: appends resume and the tree is intact (a fresh proof verifies).
    store.disarm();
    assert_eq!(log.append(vec![5; 6]), 5);
    assert_eq!(log.len(), 6);
    let proof = log.proof(5).unwrap();
    assert!(verify_block(
        &log.public_key(),
        &log.head(),
        5,
        &log.get(5).unwrap(),
        &proof
    ));
}

#[test]
fn a_failed_advance_leaves_the_replica_unchanged() {
    let seed = [2u8; 32];
    // The author's head + blocks at length 4, and the tail blocks [4, 8) to advance with.
    let (head4, blocks4) = {
        let mut a = Log::new(Keypair::from_seed(&seed));
        for i in 0..4u8 {
            a.append(vec![i; i as usize + 1]);
        }
        (
            a.head(),
            (0..4).map(|i| a.get(i).unwrap()).collect::<Vec<_>>(),
        )
    };
    let (head8, tail) = {
        let mut a = Log::new(Keypair::from_seed(&seed));
        for i in 0..8u8 {
            a.append(vec![i; i as usize + 1]);
        }
        (
            a.head(),
            (4..8).map(|i| a.get(i).unwrap()).collect::<Vec<_>>(),
        )
    };
    let pk = Keypair::from_seed(&seed).public();

    let store = Arc::new(CrashStore::new());
    let mut replica = Replica::with_store(
        pk,
        head4.clone(),
        blocks4,
        store.clone() as Arc<dyn FeedStore>,
    )
    .unwrap();
    assert_eq!(replica.len(), 4);

    store.arm();
    assert!(
        !replica.advance(head8.clone(), tail.clone()),
        "advance reports failure on a store error"
    );
    assert_eq!(replica.len(), 4, "replica unchanged after a failed advance");
    assert_eq!(replica.head(), head4, "head not advanced");
    assert!(replica.block(4).is_none(), "no new block stored");

    store.disarm();
    assert!(
        replica.advance(head8.clone(), tail),
        "advance succeeds once the store recovers"
    );
    assert_eq!(replica.len(), 8);
    assert_eq!(replica.head(), head8);
}

#[test]
fn a_failed_ingest_stores_nothing() {
    let mut author = Log::new(Keypair::from_seed(&[3; 32]));
    for i in 0..6u8 {
        author.append(vec![i; i as usize + 1]);
    }
    let pk = author.public_key();
    let head = author.head();

    let store = Arc::new(CrashStore::new());
    let mut sparse = Replica::sparse(
        pk,
        head,
        author.peak_nodes(),
        store.clone() as Arc<dyn FeedStore>,
    )
    .unwrap();
    let proof = author.proof(3).unwrap();

    store.arm();
    assert!(
        !sparse.ingest(3, author.get(3).unwrap(), &proof),
        "ingest reports failure on a store error"
    );
    assert!(
        sparse.block(3).is_none(),
        "nothing stored on a failed ingest"
    );

    store.disarm();
    assert!(sparse.ingest(3, author.get(3).unwrap(), &proof));
    assert_eq!(
        sparse.block(3),
        author.get(3),
        "the block is stored on retry"
    );
}
