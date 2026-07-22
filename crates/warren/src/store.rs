//! Generic on-disk persistence: the identity seed, the feed store + blob store, and
//! the bootstrap peer cache — so a node's identity and published content survive
//! restarts and can be re-seeded to the network next launch. Application-specific
//! state (moderation lists, UI prefs, …) is the application's own concern.
//!
//! Layout under `data_dir`:
//! ```text
//!   <seed files>          32-byte seeds (identity, node id) — named by the caller
//!   feeds.redb            the feed store — blocks + Merkle nodes + signed heads,
//!                         redb-backed ([`feed_redb`]): durable, crash-safe, not RAM-bound
//!   blobs/<hex>.bin       raw blob bytes, addressed by content id
//!   peers.json            remembered bootstrap peers we've connected to
//!   feed.jsonl            LEGACY line-per-record feed; migrated into feeds.redb on the
//!   feed.jsonl.migrated   first boot after upgrade, then renamed aside (never deleted)
//! ```

use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::record::Record;
use crate::Peer;

/// Read a persisted 32-byte seed, or generate + write a fresh random one.
pub fn load_or_create_seed(path: &Path) -> std::io::Result<[u8; 32]> {
    if let Ok(bytes) = fs::read(path) {
        if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(seed);
        }
    }
    // 32 fresh random bytes (a throwaway keypair's seed is a CSPRNG draw).
    let seed = crypto::Keypair::generate().seed();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, seed)?;
    Ok(seed)
}

/// Directory holding the raw blob files.
pub fn blobs_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("blobs")
}

/// The redb file backing every feed (own log + any mirrors).
fn feeds_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("feeds.redb")
}

/// The legacy line-per-record feed, migrated into redb on first boot.
fn legacy_feed_path(data_dir: &Path) -> PathBuf {
    data_dir.join("feed.jsonl")
}

/// A content id is lowercase hex, so it can never contain a path separator or
/// `..`. Validate before building a path from it, so a malformed or hostile
/// `blob` field (e.g. from a record synced off the network) can't escape the
/// blobs directory — the store never trusts the caller to have sanitized it.
fn is_hex_id(s: &str) -> bool {
    // Lowercase hex only: ids are produced by `to_hex` (lowercase), and accepting
    // uppercase would let a record's blob id round-trip to an on-disk path that never
    // matches the lowercase filename written elsewhere.
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn blob_path(data_dir: &Path, blob_hex: &str) -> Option<PathBuf> {
    is_hex_id(blob_hex).then(|| blobs_dir(data_dir).join(format!("{blob_hex}.bin")))
}

fn peers_path(data_dir: &Path) -> PathBuf {
    data_dir.join("peers.json")
}

/// Load the remembered peer cache (empty if absent or unreadable).
pub fn load_peer_cache(data_dir: &Path) -> Vec<Peer> {
    fs::read(peers_path(data_dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Replace the peer cache with `peers` (the caller dedups + caps). Best-effort:
/// a write failure just means we re-seed from configured bootstrap next time.
pub fn save_peer_cache(data_dir: &Path, peers: &[Peer]) {
    if let Ok(bytes) = serde_json::to_vec(peers) {
        let _ = fs::create_dir_all(data_dir);
        let _ = fs::write(peers_path(data_dir), bytes);
    }
}

/// Open the feed log (backed by the redb feed store), blob store, and record list from
/// disk. The returned [`feed::Log`] reads and writes its blocks through `feeds.redb`, so
/// appends are durable and it isn't RAM-bound.
///
/// On the first boot after upgrading from the legacy line-file: if `feed.jsonl` exists
/// and the store is still empty, its lines (which *are* the feed blocks) are replayed
/// into redb in order — reproducing the originally-published Merkle roots — and the file
/// is renamed to `feed.jsonl.migrated` (kept, never deleted, so a migration mishap can't
/// lose data). Blobs are re-ingested from their content-addressed files so we can serve
/// them.
pub fn rebuild(
    data_dir: &Path,
    keypair: crypto::Keypair,
) -> std::io::Result<(feed::Log, blob::Store, Vec<Record>)> {
    fs::create_dir_all(data_dir)?;
    let feed_store =
        feed_redb::RedbStore::create(feeds_db_path(data_dir)).map_err(std::io::Error::other)?;
    let mut log =
        feed::Log::with_store(keypair, Arc::new(feed_store)).map_err(std::io::Error::other)?;

    let legacy = legacy_feed_path(data_dir);
    if log.is_empty() && legacy.exists() {
        migrate_legacy_feed(&legacy, &mut log)?;
        let _ = fs::rename(&legacy, legacy.with_file_name("feed.jsonl.migrated"));
    }

    // Decode records + re-ingest blob bytes from the (redb-backed) log's blocks.
    let mut blobs = blob::Store::new();
    let mut records = Vec::new();
    for i in 0..log.len() {
        let Some(block) = log.get(i) else { continue };
        // The block bytes verbatim are the feed block; decoding to a Record is
        // best-effort (for the records list + blob cache). An undecodable block is
        // still a real feed block — just not surfaced as a record.
        let Ok(record) = serde_json::from_slice::<Record>(&block) else {
            continue;
        };
        if let Some(blob_hex) = &record.blob {
            if let Some(path) = blob_path(data_dir, blob_hex) {
                if let Ok(bytes) = fs::read(path) {
                    let manifest = blobs.add(&bytes);
                    blobs.put(manifest.encode());
                }
            }
        }
        records.push(record);
    }
    Ok((log, blobs, records))
}

/// Replay a legacy `feed.jsonl` into `log` (which writes through to the redb store), one
/// feed block per non-empty line, in order.
fn migrate_legacy_feed(legacy: &Path, log: &mut feed::Log) -> std::io::Result<()> {
    let file = fs::File::open(legacy)?;
    for line in std::io::BufReader::new(file).lines() {
        let line = line?; // propagate a mid-file read error rather than truncate
        if line.trim().is_empty() {
            continue;
        }
        log.try_append(line.into_bytes())
            .map_err(std::io::Error::other)?;
    }
    Ok(())
}

/// Write a blob's bytes to its content-addressed file. Kept separate from the feed
/// append (which now goes through the redb-backed [`feed::Log`]) so a caller can persist
/// a possibly-large blob outside the log lock.
pub fn write_blob(data_dir: &Path, blob_hex: &str, blob_bytes: &[u8]) -> std::io::Result<()> {
    let path = blob_path(data_dir, blob_hex)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid blob id"))?;
    fs::create_dir_all(blobs_dir(data_dir))?;
    fs::write(path, blob_bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> crypto::Keypair {
        crypto::Keypair::from_seed(&[7u8; 32])
    }

    fn record_line(blob_id: &str, bytes: &[u8]) -> String {
        let rec = Record {
            author: "aa".repeat(32),
            created_at: 100,
            content_type: "application/octet-stream".into(),
            blob: Some(blob_id.into()),
            size: bytes.len() as u64,
            body: None,
            meta: serde_json::Map::new(),
            enc: None,
            ..Default::default()
        };
        serde_json::to_string(&rec).unwrap()
    }

    #[test]
    fn peer_cache_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_peer_cache(dir.path()).is_empty(), "empty before save");
        let peers = vec![
            Peer {
                node_id: "ab".repeat(32),
                addr: "1.2.3.4:9000".into(),
            },
            Peer {
                node_id: "cd".repeat(32),
                addr: "[2001:db8::1]:7000".into(),
            },
        ];
        save_peer_cache(dir.path(), &peers);
        assert_eq!(load_peer_cache(dir.path()), peers);
    }

    #[test]
    fn published_feed_survives_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        // Publish two blob-bearing records through a redb-backed log at the data dir
        // (what a session does), then drop it so redb releases the file.
        {
            let mut log = feed::Log::with_store(
                kp(),
                Arc::new(feed_redb::RedbStore::create(feeds_db_path(dir.path())).unwrap()),
            )
            .unwrap();
            for (id, bytes) in [("aa01", &b"first blob"[..]), ("aa02", &b"second blob"[..])] {
                write_blob(dir.path(), id, bytes).unwrap();
                log.append(record_line(id, bytes).into_bytes());
            }
        }
        let (log, _blobs, records) = rebuild(dir.path(), kp()).unwrap();
        assert_eq!(records.len(), 2, "both records restored from redb");
        assert_eq!(log.len(), 2, "both feed blocks restored");
        assert_eq!(records[0].blob.as_deref(), Some("aa01"));
        assert_eq!(records[1].content_type, "application/octet-stream");
    }

    #[test]
    fn rebuild_migrates_a_legacy_feed_jsonl_into_redb() {
        let dir = tempfile::tempdir().unwrap();
        // A pre-upgrade node: feed.jsonl with two record lines + their blob files.
        let mut lines = String::new();
        for (id, bytes) in [("bb01", &b"one"[..]), ("bb02", &b"two"[..])] {
            write_blob(dir.path(), id, bytes).unwrap();
            lines.push_str(&record_line(id, bytes));
            lines.push('\n');
        }
        fs::write(legacy_feed_path(dir.path()), lines).unwrap();

        // First boot after upgrade: rebuild migrates the legacy file into redb.
        let first = {
            let (log, _blobs, records) = rebuild(dir.path(), kp()).unwrap();
            assert_eq!(records.len(), 2, "legacy records migrated");
            assert_eq!(log.len(), 2);
            assert!(
                !legacy_feed_path(dir.path()).exists(),
                "legacy file renamed aside"
            );
            assert!(
                dir.path().join("feed.jsonl.migrated").exists(),
                "kept as .migrated, not deleted"
            );
            records.len()
        }; // log (and its redb Database) dropped here, releasing the file
        assert_eq!(first, 2);

        // Second boot: redb already holds the feed; no re-migration, data intact.
        let (log2, _b2, records2) = rebuild(dir.path(), kp()).unwrap();
        assert_eq!(records2.len(), 2, "feed persists in redb across reopen");
        assert_eq!(log2.len(), 2);
    }

    #[test]
    fn write_blob_rejects_a_non_hex_id() {
        // A blob id is always lowercase hex; anything else (path separators, `..`,
        // non-hex) is rejected before it can touch the filesystem.
        let dir = tempfile::tempdir().unwrap();
        for bad in ["../escape", "a/b", "..", "zz", ""] {
            assert!(
                write_blob(dir.path(), bad, b"x").is_err(),
                "rejected {bad:?}"
            );
        }
    }
}
