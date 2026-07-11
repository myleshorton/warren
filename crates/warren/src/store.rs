//! Generic on-disk persistence: the identity seed, the feed log + blob store, and
//! the bootstrap peer cache — so a node's identity and published content survive
//! restarts and can be re-seeded to the network next launch. Application-specific
//! state (moderation lists, UI prefs, …) is the application's own concern.
//!
//! Layout under `data_dir`:
//! ```text
//!   <seed files>        32-byte seeds (identity, node id) — named by the caller
//!   feed.jsonl          one JSON `Record` per line, in publish order — these
//!                       lines ARE the feed blocks (stored verbatim so the rebuilt
//!                       log reproduces identical Merkle roots)
//!   blobs/<hex>.bin     raw blob bytes, addressed by content id
//!   peers.json          remembered bootstrap peers we've connected to
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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

fn feed_path(data_dir: &Path) -> PathBuf {
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

/// Rebuild the in-memory feed log, blob store, and record list from disk. The feed
/// blocks are the raw `feed.jsonl` lines, appended in order so the rebuilt log's
/// roots match what was originally published.
pub fn rebuild(
    data_dir: &Path,
    keypair: crypto::Keypair,
) -> std::io::Result<(feed::Log, blob::Store, Vec<Record>)> {
    let mut log = feed::Log::new(keypair);
    let mut store = blob::Store::new();
    let mut records = Vec::new();

    let raw = fs::read_to_string(feed_path(data_dir)).unwrap_or_default();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Record>(line) else {
            continue; // skip a corrupt line rather than fail the whole rebuild
        };
        // The line verbatim is the feed block.
        log.append(line.as_bytes().to_vec());
        // Re-ingest the blob bytes so we can serve them (content-addressed, so
        // re-splitting reproduces the same manifest/blob id).
        if let Some(blob_hex) = &record.blob {
            if let Some(path) = blob_path(data_dir, blob_hex) {
                if let Ok(bytes) = fs::read(path) {
                    let manifest = store.add(&bytes);
                    store.put(manifest.encode());
                }
            }
        }
        records.push(record);
    }
    Ok((log, store, records))
}

/// Persist a freshly published record: write its blob bytes and append its
/// feed-block line. `line` must be exactly the bytes appended to the feed.
pub fn append_record(
    data_dir: &Path,
    blob_hex: &str,
    blob_bytes: &[u8],
    line: &str,
) -> std::io::Result<()> {
    let path = blob_path(data_dir, blob_hex)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid blob id"))?;
    fs::create_dir_all(blobs_dir(data_dir))?;
    fs::write(path, blob_bytes)?;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(feed_path(data_dir))?;
    writeln!(f, "{line}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn append_then_rebuild_restores_records_and_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let kp = crypto::Keypair::generate();

        // Publish two records with blob payloads.
        let blob = |id: &str, bytes: &[u8]| -> String {
            let rec = Record {
                author: "aa".repeat(32),
                created_at: 100,
                content_type: "application/octet-stream".into(),
                blob: Some(id.into()),
                size: bytes.len() as u64,
                body: None,
                meta: serde_json::Map::new(),
                enc: None,
                ..Default::default()
            };
            serde_json::to_string(&rec).unwrap()
        };
        append_record(
            dir.path(),
            "aa01",
            b"first blob",
            &blob("aa01", b"first blob"),
        )
        .unwrap();
        append_record(
            dir.path(),
            "aa02",
            b"second blob",
            &blob("aa02", b"second blob"),
        )
        .unwrap();

        let (log, _store, records) = rebuild(dir.path(), kp).unwrap();
        assert_eq!(records.len(), 2, "both records restored");
        assert_eq!(log.len(), 2, "both feed blocks restored");
        assert_eq!(records[0].blob.as_deref(), Some("aa01"));
        assert_eq!(records[1].content_type, "application/octet-stream");
    }

    #[test]
    fn append_rejects_non_hex_blob_id() {
        // A blob id is always lowercase hex; anything else (path separators, `..`,
        // non-hex) is rejected before it can touch the filesystem.
        let dir = tempfile::tempdir().unwrap();
        for bad in ["../escape", "a/b", "..", "zz", ""] {
            assert!(
                append_record(dir.path(), bad, b"x", "{}").is_err(),
                "rejected {bad:?}"
            );
        }
    }
}
