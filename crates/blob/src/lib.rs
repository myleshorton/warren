//! A content-addressed store for large immutable blobs — the data layer's
//! complement to [`feed`](../feed).
//!
//! Where a `feed` is a *signed*, ordered, append-only log (mutable over time,
//! one author), a blob is *immutable* data addressed by the hash of its content.
//! Content addressing is self-verifying: a chunk's BLAKE3 hash **is** its name,
//! so a peer can fetch a chunk from anyone and check it by rehashing — no
//! signature, and identical content dedups across the whole network.
//!
//! A blob is split into fixed-size chunks; a [`Manifest`] lists the chunk hashes
//! in order plus the total length, and the manifest's own hash ([`Manifest::id`])
//! is the blob's content address. Publish that id (in a signed feed, or on the
//! DHT) and a viewer can pull the manifest, then fetch and verify each chunk by
//! hash from any peer, and reassemble — the shape a P2P video download takes.
//!
//! Pure and synchronous: no I/O, no clock. The sync protocol layers on top.
//!
//! ```
//! use blob::{split, verify_chunk, Store};
//!
//! let data = vec![7u8; 200_000];
//! let (manifest, chunks) = split(&data);
//!
//! // A peer fetches chunks by hash and verifies each before storing.
//! let mut store = Store::new();
//! for (i, chunk) in chunks.iter().enumerate() {
//!     assert!(verify_chunk(&manifest.chunks[i], chunk));
//!     store.put(chunk.clone());
//! }
//! assert_eq!(store.reassemble(&manifest).as_deref(), Some(data.as_slice()));
//! ```

use std::collections::HashMap;

use crypto::{hash, Hash, HASH_LEN};
use thiserror::Error;
use wire::{Decoder, Encoder, WireError};

/// Default chunk size a blob is split into: 64 KiB. Every chunk but the last is
/// exactly this size.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// An ordered list of content-addressed chunks that reconstruct a blob, plus its
/// total length. The manifest's own hash ([`Manifest::id`]) is the blob's
/// content address — any change to the chunk list or length yields a new id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Total length of the blob in bytes.
    pub total_len: u64,
    /// Hash of each chunk, in order. Concatenating the chunks reconstructs the
    /// blob; identical chunks share a hash (dedup).
    pub chunks: Vec<Hash>,
}

impl Manifest {
    /// The blob's content address: the hash of the manifest's encoding. Fetch a
    /// blob by publishing this; a decoded manifest whose `id` matches is intact.
    pub fn id(&self) -> Hash {
        hash(&self.encode())
    }

    /// Encode the manifest for transfer.
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.uint(self.total_len);
        enc.uint(self.chunks.len() as u64);
        for chunk in &self.chunks {
            enc.raw(chunk);
        }
        enc.into_vec()
    }

    /// Decode a manifest from bytes.
    pub fn decode(buf: &[u8]) -> Result<Manifest, BlobError> {
        let mut dec = Decoder::new(buf);
        let total_len = dec.uint()?;
        let count = dec.uint()?;
        // Each chunk hash is fixed-size; bound the count by the buffer so a
        // crafted length can't force a huge allocation.
        if count > dec.remaining() as u64 / HASH_LEN as u64 {
            return Err(BlobError::Malformed("chunk count exceeds buffer"));
        }
        let mut chunks = Vec::with_capacity(count as usize);
        for _ in 0..count {
            chunks.push(dec.array::<HASH_LEN>()?);
        }
        dec.finish()?;
        Ok(Manifest { total_len, chunks })
    }
}

/// Split `data` into [`CHUNK_SIZE`] chunks, returning the [`Manifest`] and the
/// chunk bytes (in the same order as `manifest.chunks`). Empty input yields an
/// empty manifest and no chunks.
pub fn split(data: &[u8]) -> (Manifest, Vec<Vec<u8>>) {
    split_with(data, CHUNK_SIZE)
}

/// Like [`split`], with an explicit chunk size. Panics if `chunk_size == 0`.
pub fn split_with(data: &[u8], chunk_size: usize) -> (Manifest, Vec<Vec<u8>>) {
    assert!(chunk_size > 0, "chunk size must be non-zero");
    let chunks: Vec<Vec<u8>> = data.chunks(chunk_size).map(<[u8]>::to_vec).collect();
    let manifest = Manifest {
        total_len: data.len() as u64,
        chunks: chunks.iter().map(|c| hash(c)).collect(),
    };
    (manifest, chunks)
}

/// Whether `bytes` is the chunk named by `hash` — content addressing is
/// self-verifying, so the hash is the only credential a chunk needs.
pub fn verify_chunk(hash_of_chunk: &Hash, bytes: &[u8]) -> bool {
    hash(bytes) == *hash_of_chunk
}

/// An in-memory content-addressed store: chunks keyed by their hash. Putting the
/// same content twice is a no-op (dedup); a `get` returns content that hashes to
/// the requested key, so callers can trust what they read back.
#[derive(Debug, Default)]
pub struct Store {
    chunks: HashMap<Hash, Vec<u8>>,
}

impl Store {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `bytes` under its content hash, returning that hash. Idempotent for
    /// identical content.
    pub fn put(&mut self, bytes: Vec<u8>) -> Hash {
        let key = hash(&bytes);
        self.chunks.entry(key).or_insert(bytes);
        key
    }

    /// The chunk stored under `hash`, if present.
    pub fn get(&self, hash: &Hash) -> Option<&[u8]> {
        self.chunks.get(hash).map(Vec::as_slice)
    }

    /// Whether a chunk with this hash is stored.
    pub fn has(&self, hash: &Hash) -> bool {
        self.chunks.contains_key(hash)
    }

    /// Number of distinct chunks stored.
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the store holds no chunks.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Split `data` into chunks, store them, and return the manifest — the
    /// convenience path for putting a whole blob at once.
    pub fn add(&mut self, data: &[u8]) -> Manifest {
        let (manifest, chunks) = split(data);
        for chunk in chunks {
            self.put(chunk);
        }
        manifest
    }

    /// Reassemble the blob described by `manifest` from stored chunks, or `None`
    /// if any chunk is missing or the result doesn't match the manifest's total
    /// length (a structural integrity check on top of per-chunk addressing).
    pub fn reassemble(&self, manifest: &Manifest) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(manifest.total_len.min(1 << 20) as usize);
        for chunk_hash in &manifest.chunks {
            out.extend_from_slice(self.get(chunk_hash)?);
        }
        (out.len() as u64 == manifest.total_len).then_some(out)
    }
}

/// Errors decoding a [`Manifest`] from bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BlobError {
    /// A length field exceeded what the buffer could hold.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// The underlying byte codec rejected the buffer.
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_then_reassemble_roundtrips() {
        // A blob spanning several chunks plus a partial last chunk.
        let data: Vec<u8> = (0..CHUNK_SIZE * 2 + 123).map(|i| i as u8).collect();
        let mut store = Store::new();
        let manifest = store.add(&data);
        assert_eq!(manifest.chunks.len(), 3);
        assert_eq!(manifest.total_len, data.len() as u64);
        assert_eq!(store.reassemble(&manifest), Some(data));
    }

    #[test]
    fn empty_blob_has_no_chunks() {
        let mut store = Store::new();
        let manifest = store.add(&[]);
        assert_eq!(manifest.total_len, 0);
        assert!(manifest.chunks.is_empty());
        assert_eq!(store.reassemble(&manifest), Some(Vec::new()));
    }

    #[test]
    fn a_chunk_verifies_only_against_its_own_hash() {
        let (manifest, chunks) = split_with(b"hello world", 4);
        assert!(verify_chunk(&manifest.chunks[0], &chunks[0]));
        assert!(!verify_chunk(&manifest.chunks[0], b"nope"));
    }

    #[test]
    fn identical_chunks_dedup() {
        let data = vec![9u8; CHUNK_SIZE * 3]; // three identical full chunks
        let mut store = Store::new();
        let manifest = store.add(&data);
        assert_eq!(manifest.chunks.len(), 3);
        // All three chunk hashes are equal, so the store holds just one.
        assert_eq!(store.len(), 1);
        assert_eq!(store.reassemble(&manifest), Some(data));
    }

    #[test]
    fn reassemble_fails_on_a_missing_chunk() {
        let data = vec![1u8; CHUNK_SIZE + 1];
        let (manifest, _chunks) = split(&data);
        let store = Store::new(); // nothing stored
        assert_eq!(store.reassemble(&manifest), None);
    }

    #[test]
    fn reassemble_fails_when_total_len_disagrees() {
        let data = vec![2u8; 100];
        let mut store = Store::new();
        let mut manifest = store.add(&data);
        manifest.total_len = 999; // tamper
        assert_eq!(store.reassemble(&manifest), None);
    }

    #[test]
    fn manifest_id_pins_the_chunk_list() {
        let a = split(b"the quick brown fox").0;
        let mut b = a.clone();
        assert_eq!(a.id(), b.id());
        b.chunks.push([0u8; HASH_LEN]); // any change
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn manifest_roundtrips_and_rejects_trailing_bytes() {
        let manifest = split(&vec![0u8; CHUNK_SIZE * 2 + 7]).0;
        assert_eq!(Manifest::decode(&manifest.encode()).unwrap(), manifest);
        let mut bytes = manifest.encode();
        bytes.push(0xff);
        assert!(matches!(
            Manifest::decode(&bytes),
            Err(BlobError::Wire(WireError::TrailingBytes(1)))
        ));
    }
}
