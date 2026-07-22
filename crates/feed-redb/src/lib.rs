//! A disk-backed [`feed::FeedStore`] on [redb](https://docs.rs/redb) — an embedded,
//! ACID, pure-Rust key-value store.
//!
//! This crate exists so redb's dependency stays out of the pure `feed` crate (whose
//! `MemStore` keeps the deterministic simulator and tests dependency-free). Production
//! code — `warren`, `murmur` — depends on `feed-redb` to get durable, crash-safe,
//! disk-native feed storage that isn't bound by RAM.
//!
//! Layout: one redb file holding three tables, keyed by `feed_key ‖ big-endian index` so
//! a feed's blocks/nodes are a contiguous, index-ordered key range:
//!
//! | table    | key                    | value                     |
//! |----------|------------------------|---------------------------|
//! | `blocks` | `feed(32) ‖ index(8)`  | block bytes               |
//! | `nodes`  | `feed(32) ‖ index(8)`  | 32-byte Merkle node hash  |
//! | `heads`  | `feed(32)`             | [`feed::Head::encode`] bytes |
//!
//! A [`feed::Batch`] commits as one redb write transaction, so an append is atomic: a
//! crash mid-commit leaves the last committed state intact.

use crypto::Hash;
use feed::{Batch, FeedKey, FeedStore, Head, StoreError, StoreResult};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

// Key type is `&[u8]` (lexicographically ordered → our `feed ‖ index_be` composite sorts
// feed-grouped, index-ascending). Values are opaque bytes.
const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nodes");
const HEADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("heads");

/// Map any redb error to a [`StoreError`].
fn be(e: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// The composite key `feed_key ‖ big-endian index` (40 bytes).
fn composite(feed: &FeedKey, index: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(feed);
    key[32..].copy_from_slice(&index.to_be_bytes());
    key
}

/// A [`FeedStore`] backed by a single redb database file.
#[derive(Clone)]
pub struct RedbStore {
    db: Arc<Database>,
}

impl RedbStore {
    /// Create or open the store at `path`.
    pub fn create(path: impl AsRef<Path>) -> StoreResult<Self> {
        let db = Database::create(path).map_err(be)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Wrap an already-open redb database (e.g. one shared with a blob store).
    pub fn from_db(db: Arc<Database>) -> Self {
        Self { db }
    }
}

impl FeedStore for RedbStore {
    fn commit(&self, feed: &FeedKey, batch: Batch) -> StoreResult<()> {
        let txn = self.db.begin_write().map_err(be)?;
        {
            if !batch.blocks.is_empty() {
                let mut t = txn.open_table(BLOCKS).map_err(be)?;
                for (index, bytes) in &batch.blocks {
                    t.insert(composite(feed, *index).as_slice(), bytes.as_slice())
                        .map_err(be)?;
                }
            }
            if !batch.nodes.is_empty() {
                let mut t = txn.open_table(NODES).map_err(be)?;
                for (index, hash) in &batch.nodes {
                    t.insert(composite(feed, *index).as_slice(), hash.as_slice())
                        .map_err(be)?;
                }
            }
            if let Some(head) = &batch.head {
                let mut t = txn.open_table(HEADS).map_err(be)?;
                t.insert(feed.as_slice(), head.encode().as_slice())
                    .map_err(be)?;
            }
        }
        txn.commit().map_err(be)?;
        Ok(())
    }

    fn block(&self, feed: &FeedKey, index: u64) -> StoreResult<Option<Vec<u8>>> {
        let txn = self.db.begin_read().map_err(be)?;
        let Ok(table) = txn.open_table(BLOCKS) else {
            return Ok(None); // table absent = nothing committed yet
        };
        Ok(table
            .get(composite(feed, index).as_slice())
            .map_err(be)?
            .map(|g| g.value().to_vec()))
    }

    fn node(&self, feed: &FeedKey, index: u64) -> StoreResult<Option<Hash>> {
        let txn = self.db.begin_read().map_err(be)?;
        let Ok(table) = txn.open_table(NODES) else {
            return Ok(None);
        };
        let Some(guard) = table.get(composite(feed, index).as_slice()).map_err(be)? else {
            return Ok(None);
        };
        let hash: Hash = guard
            .value()
            .try_into()
            .map_err(|_| StoreError::Backend("node hash is not 32 bytes".into()))?;
        Ok(Some(hash))
    }

    fn head(&self, feed: &FeedKey) -> StoreResult<Option<Head>> {
        let txn = self.db.begin_read().map_err(be)?;
        let Ok(table) = txn.open_table(HEADS) else {
            return Ok(None);
        };
        let Some(guard) = table.get(feed.as_slice()).map_err(be)? else {
            return Ok(None);
        };
        Ok(Some(Head::decode(guard.value()).map_err(be)?))
    }

    fn has_block(&self, feed: &FeedKey, index: u64) -> StoreResult<bool> {
        let txn = self.db.begin_read().map_err(be)?;
        let Ok(table) = txn.open_table(BLOCKS) else {
            return Ok(false);
        };
        Ok(table
            .get(composite(feed, index).as_slice())
            .map_err(be)?
            .is_some())
    }

    fn contiguous_len(&self, feed: &FeedKey) -> StoreResult<u64> {
        let txn = self.db.begin_read().map_err(be)?;
        let Ok(table) = txn.open_table(BLOCKS) else {
            return Ok(0);
        };
        // One read snapshot; walk 0,1,2,… until the first gap. mmap reads are cheap.
        let mut len = 0u64;
        while table
            .get(composite(feed, len).as_slice())
            .map_err(be)?
            .is_some()
        {
            len += 1;
        }
        Ok(len)
    }

    fn feeds(&self) -> StoreResult<Vec<FeedKey>> {
        let txn = self.db.begin_read().map_err(be)?;
        let Ok(table) = txn.open_table(HEADS) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for entry in table.iter().map_err(be)? {
            let (key, _) = entry.map_err(be)?;
            if let Ok(feed) = <FeedKey>::try_from(key.value()) {
                out.push(feed);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use feed::{leaf_hash, Log};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fresh redb file under the temp dir, removed on drop.
    struct TempDb(RedbStore, PathBuf);
    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.1);
        }
    }
    fn temp() -> TempDb {
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "feed-redb-{}-{}.redb",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        TempDb(RedbStore::create(&path).unwrap(), path)
    }

    fn feed_key(b: u8) -> FeedKey {
        [b; 32]
    }

    #[test]
    fn commit_then_read_across_all_tables() {
        let db = temp();
        let s = &db.0;
        let f = feed_key(7);
        s.commit(
            &f,
            Batch {
                blocks: vec![(0, b"zero".to_vec()), (1, b"one".to_vec())],
                nodes: vec![(0, leaf_hash(b"zero"))],
                head: None,
            },
        )
        .unwrap();
        assert_eq!(s.block(&f, 0).unwrap().as_deref(), Some(&b"zero"[..]));
        assert_eq!(s.block(&f, 1).unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(s.block(&f, 2).unwrap(), None);
        assert_eq!(s.node(&f, 0).unwrap(), Some(leaf_hash(b"zero")));
        assert!(s.has_block(&f, 1).unwrap());
        assert_eq!(s.contiguous_len(&f).unwrap(), 2);
    }

    #[test]
    fn contiguous_len_stops_at_the_first_gap() {
        let db = temp();
        let s = &db.0;
        let f = feed_key(1);
        s.commit(
            &f,
            Batch {
                blocks: vec![(0, vec![0]), (1, vec![1]), (3, vec![3])],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(s.contiguous_len(&f).unwrap(), 2);
        assert!(s.has_block(&f, 3).unwrap());
    }

    #[test]
    fn a_log_over_redb_matches_a_log_over_memstore() {
        // Parity: the store is invisible to the crypto — identical appends yield an
        // identical signed head whether backed by MemStore or RedbStore.
        let db = temp();
        let seed = [9u8; 32];
        let redb_head = {
            let mut log =
                Log::with_store(crypto::Keypair::from_seed(&seed), Arc::new(db.0.clone())).unwrap();
            for i in 0..6u8 {
                log.append(vec![i; i as usize + 1]);
            }
            log.head()
        };
        let mem_head = {
            let mut log = Log::new(crypto::Keypair::from_seed(&seed));
            for i in 0..6u8 {
                log.append(vec![i; i as usize + 1]);
            }
            log.head()
        };
        assert_eq!(
            redb_head, mem_head,
            "a redb-backed log produces the same head as a mem-backed one"
        );
    }

    #[test]
    fn a_feed_survives_reopening_the_database() {
        // Cross-restart durability: append over one Database, drop it, reopen the same
        // file, and the feed rebuilds intact (identical head, readable blocks).
        let path = std::env::temp_dir().join(format!(
            "feed-redb-reopen-{}-{}.redb",
            std::process::id(),
            42
        ));
        let _ = std::fs::remove_file(&path);
        let seed = [3u8; 32];

        let head_before = {
            let store = Arc::new(RedbStore::create(&path).unwrap());
            let mut log = Log::with_store(crypto::Keypair::from_seed(&seed), store).unwrap();
            for i in 0..4u8 {
                log.append(vec![i; i as usize + 1]);
            }
            log.head()
        };

        // A brand-new Database over the same file — simulating an app restart.
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let reopened = Log::with_store(crypto::Keypair::from_seed(&seed), store).unwrap();
        assert_eq!(reopened.len(), 4);
        assert_eq!(reopened.head(), head_before, "head survived the restart");
        assert_eq!(reopened.get(2).as_deref(), Some([2u8; 3].as_slice()));

        let _ = std::fs::remove_file(&path);
    }
}
