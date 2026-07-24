//! Pluggable storage for a feed's blocks, Merkle nodes, and signed head.
//!
//! [`Log`](crate::Log) and [`Replica`](crate::Replica) hold their bytes in RAM today.
//! To let a node hold large or many feeds without becoming memory-bound — and to make a
//! mirror durable across restarts — their storage moves behind [`FeedStore`]: blocks,
//! tree nodes, and the signed head, read and written by (feed key, index).
//!
//! The trait is the seam that keeps the sans-IO discipline intact. [`MemStore`] is a pure,
//! in-memory backend used by the deterministic simulator and tests; a disk-backed backend
//! (redb) lives behind a feature/crate so its dependency never reaches this pure layer.
//! An append is a [`Batch`] — new blocks, the nodes they produce, and the new head —
//! committed **atomically**, so a crash mid-write can never leave a torn feed.

use crate::Head;
use crypto::Hash;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;
use thiserror::Error;

/// A feed's stable identity: its owner's ed25519 public-key bytes.
pub type FeedKey = [u8; 32];

/// A storage-backend failure. [`MemStore`] never returns one; a disk backend maps its
/// engine errors here so the pure layer needn't know the engine.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The backend failed (I/O, corruption, a poisoned lock).
    #[error("feed store backend error: {0}")]
    Backend(String),
}

/// Result of a [`FeedStore`] operation.
pub type StoreResult<T> = Result<T, StoreError>;

/// One atomic unit of feed growth: the new blocks, the Merkle nodes they produce, and
/// the new signed head — all committed together by [`FeedStore::commit`] or not at all.
///
/// An empty `Batch` is a no-op. `nodes` is keyed by node index (leaf hashes today; the
/// full flat-tree once O(log n) proofs land) and may be empty for a backend that
/// recomputes the tree from blocks.
#[derive(Debug, Default, Clone)]
pub struct Batch {
    /// `(block index, block bytes)` to write.
    pub blocks: Vec<(u64, Vec<u8>)>,
    /// `(node index, node hash)` to write.
    pub nodes: Vec<(u64, Hash)>,
    /// The feed's new signed head, if it advanced.
    pub head: Option<Head>,
}

/// Where a feed's blocks, nodes, and head live.
///
/// Keyed by `(feed, index)` so one store holds many feeds (an owner's own log plus every
/// feed it mirrors). Reads return `None` for anything absent — a store may hold a *sparse*
/// subset of a feed. [`commit`](FeedStore::commit) is atomic; every other method is a read.
pub trait FeedStore: Send + Sync {
    /// Apply `batch` to `feed` atomically — all of it becomes durable, or none of it.
    fn commit(&self, feed: &FeedKey, batch: Batch) -> StoreResult<()>;
    /// Prune `feed` to a suffix window, atomically: drop every block with index
    /// `< retain_from`, and every Merkle node whose index is **not** in `retain_nodes`.
    /// The caller ([`Replica::prune`](crate::Replica::prune)) sets `retain_nodes` to the
    /// peaks plus every retained block's audit path, so kept blocks stay provable while the
    /// rest is reclaimed. The head and length are untouched — the feed still knows its shape.
    /// A no-op for a feed the store doesn't hold.
    fn prune(
        &self,
        feed: &FeedKey,
        retain_from: u64,
        retain_nodes: &BTreeSet<u64>,
    ) -> StoreResult<()>;
    /// The block at `index`, if held.
    fn block(&self, feed: &FeedKey, index: u64) -> StoreResult<Option<Vec<u8>>>;
    /// The Merkle node at `index`, if held.
    fn node(&self, feed: &FeedKey, index: u64) -> StoreResult<Option<Hash>>;
    /// The feed's latest signed head, if any block has been committed.
    fn head(&self, feed: &FeedKey) -> StoreResult<Option<Head>>;
    /// Whether the block at `index` is held (a feed may be sparse).
    fn has_block(&self, feed: &FeedKey, index: u64) -> StoreResult<bool>;
    /// The length of the contiguous run of blocks present from index 0 — the dense length
    /// of a full feed, and how far a rebuild can reconstruct the tree before hitting a gap.
    fn contiguous_len(&self, feed: &FeedKey) -> StoreResult<u64>;
    /// Every feed this store holds anything for (own log + mirrors).
    fn feeds(&self) -> StoreResult<Vec<FeedKey>>;
}

/// One feed's storage inside [`MemStore`]. `BTreeMap` keeps blocks/nodes index-ordered so
/// range and contiguous-prefix queries are natural.
#[derive(Default)]
struct FeedData {
    blocks: BTreeMap<u64, Vec<u8>>,
    nodes: BTreeMap<u64, Hash>,
    head: Option<Head>,
}

/// A pure, in-memory [`FeedStore`] for the simulator and tests. Holds everything in a
/// single map behind one lock, so a [`commit`](FeedStore::commit) is trivially atomic —
/// it models the disk backend's all-or-nothing transaction without touching disk.
#[derive(Default)]
pub struct MemStore {
    inner: Mutex<HashMap<FeedKey, FeedData>>,
}

impl MemStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> StoreResult<std::sync::MutexGuard<'_, HashMap<FeedKey, FeedData>>> {
        self.inner
            .lock()
            .map_err(|_| StoreError::Backend("mem store lock poisoned".into()))
    }
}

impl FeedStore for MemStore {
    fn commit(&self, feed: &FeedKey, batch: Batch) -> StoreResult<()> {
        let mut map = self.lock()?;
        let data = map.entry(*feed).or_default();
        for (index, bytes) in batch.blocks {
            data.blocks.insert(index, bytes);
        }
        for (index, hash) in batch.nodes {
            data.nodes.insert(index, hash);
        }
        if let Some(head) = batch.head {
            data.head = Some(head);
        }
        Ok(())
    }

    fn prune(
        &self,
        feed: &FeedKey,
        retain_from: u64,
        retain_nodes: &BTreeSet<u64>,
    ) -> StoreResult<()> {
        let mut map = self.lock()?;
        if let Some(data) = map.get_mut(feed) {
            data.blocks.retain(|&k, _| k >= retain_from);
            data.nodes.retain(|&k, _| retain_nodes.contains(&k));
        }
        Ok(())
    }

    fn block(&self, feed: &FeedKey, index: u64) -> StoreResult<Option<Vec<u8>>> {
        Ok(self
            .lock()?
            .get(feed)
            .and_then(|d| d.blocks.get(&index).cloned()))
    }

    fn node(&self, feed: &FeedKey, index: u64) -> StoreResult<Option<Hash>> {
        Ok(self
            .lock()?
            .get(feed)
            .and_then(|d| d.nodes.get(&index).cloned()))
    }

    fn head(&self, feed: &FeedKey) -> StoreResult<Option<Head>> {
        Ok(self.lock()?.get(feed).and_then(|d| d.head.clone()))
    }

    fn has_block(&self, feed: &FeedKey, index: u64) -> StoreResult<bool> {
        Ok(self
            .lock()?
            .get(feed)
            .is_some_and(|d| d.blocks.contains_key(&index)))
    }

    fn contiguous_len(&self, feed: &FeedKey) -> StoreResult<u64> {
        let map = self.lock()?;
        let Some(data) = map.get(feed) else {
            return Ok(0);
        };
        // The prefix is dense from 0, so the first gap is the length. BTreeMap is ordered,
        // so walk keys until one skips ahead of the running count.
        let mut len = 0u64;
        for &index in data.blocks.keys() {
            if index != len {
                break;
            }
            len += 1;
        }
        Ok(len)
    }

    fn feeds(&self) -> StoreResult<Vec<FeedKey>> {
        Ok(self.lock()?.keys().copied().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{leaf_hash, Log};
    use crypto::Keypair;

    fn key(b: u8) -> FeedKey {
        [b; 32]
    }

    /// A real signed head to round-trip (the store treats it as opaque, but using a
    /// genuine one proves the encoded form survives).
    fn a_head() -> (FeedKey, Head) {
        let kp = Keypair::generate();
        let mut log = Log::new(kp);
        log.append(b"only");
        (log.public_key().to_bytes(), log.head())
    }

    #[test]
    fn commit_then_read_blocks_nodes_head() {
        let s = MemStore::new();
        let (f, head) = a_head();
        s.commit(
            &f,
            Batch {
                blocks: vec![(0, b"zero".to_vec()), (1, b"one".to_vec())],
                nodes: vec![(0, leaf_hash(b"zero")), (1, leaf_hash(b"one"))],
                head: Some(head.clone()),
            },
        )
        .unwrap();

        assert_eq!(s.block(&f, 0).unwrap().as_deref(), Some(&b"zero"[..]));
        assert_eq!(s.block(&f, 1).unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(s.block(&f, 2).unwrap(), None);
        assert_eq!(s.node(&f, 1).unwrap(), Some(leaf_hash(b"one")));
        assert_eq!(s.head(&f).unwrap(), Some(head));
    }

    #[test]
    fn unknown_feed_reads_empty() {
        let s = MemStore::new();
        let f = key(9);
        assert_eq!(s.block(&f, 0).unwrap(), None);
        assert_eq!(s.head(&f).unwrap(), None);
        assert!(!s.has_block(&f, 0).unwrap());
        assert_eq!(s.contiguous_len(&f).unwrap(), 0);
    }

    #[test]
    fn contiguous_len_stops_at_the_first_gap() {
        let s = MemStore::new();
        let f = key(1);
        // A sparse feed: 0, 1, then a gap, then 3.
        s.commit(
            &f,
            Batch {
                blocks: vec![(0, vec![0]), (1, vec![1]), (3, vec![3])],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(s.has_block(&f, 3).unwrap());
        assert!(!s.has_block(&f, 2).unwrap());
        assert_eq!(
            s.contiguous_len(&f).unwrap(),
            2,
            "the dense prefix is [0,1]; block 3 is past the gap at 2"
        );
    }

    #[test]
    fn later_commit_overwrites_a_block_and_advances_head() {
        let s = MemStore::new();
        let (f, h1) = a_head();
        s.commit(
            &f,
            Batch {
                blocks: vec![(0, b"first".to_vec())],
                head: Some(h1),
                ..Default::default()
            },
        )
        .unwrap();
        let (_, h2) = a_head();
        s.commit(
            &f,
            Batch {
                blocks: vec![(0, b"second".to_vec())],
                head: Some(h2.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(s.block(&f, 0).unwrap().as_deref(), Some(&b"second"[..]));
        assert_eq!(s.head(&f).unwrap(), Some(h2));
    }

    #[test]
    fn feeds_lists_every_committed_feed() {
        let s = MemStore::new();
        let (a, _) = (key(1), ());
        let (b, _) = (key(2), ());
        s.commit(
            &a,
            Batch {
                blocks: vec![(0, vec![0])],
                ..Default::default()
            },
        )
        .unwrap();
        s.commit(
            &b,
            Batch {
                blocks: vec![(0, vec![0])],
                ..Default::default()
            },
        )
        .unwrap();
        let mut feeds = s.feeds().unwrap();
        feeds.sort();
        assert_eq!(feeds, vec![a, b]);
    }
}
