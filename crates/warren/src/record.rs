//! The general signed-record envelope + its encryption metadata.
//!
//! A record is one block in a creator's signed [`feed`] log. It is
//! deliberately content-agnostic: `content_type` says what the payload is, a small
//! payload can ride inline in `body`, a large one is a content-addressed `blob`
//! attachment, and `meta` carries whatever app-specific fields an application needs
//! (a video title, a chat reply-to, …). `enc` is present when the payload is
//! encrypted. Murmur's video post is one specialization; a chat message is another.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{merge, util};

/// A signed feed record, content-agnostic.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Record {
    /// The author's feed public key (hex) — the content identity. Often implied by
    /// the feed a record lives in, but carried explicitly for merged views.
    pub author: String,
    /// Unix seconds when published.
    pub created_at: u64,
    /// What the payload is (application-defined, e.g. `"video/mp4"`, `"text/plain"`).
    pub content_type: String,
    /// Hex of a content-addressed blob id, when the payload is a blob attachment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    /// Plaintext size of the blob attachment, in bytes.
    #[serde(default)]
    pub size: u64,
    /// A small inline payload (e.g. a chat message), for records carrying no blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Application-specific fields (a video title + thumbnail, a reply-to id, …).
    #[serde(default, skip_serializing_if = "is_empty_map")]
    pub meta: serde_json::Map<String, serde_json::Value>,
    /// Encryption envelope; present ⇒ `blob` / `body` are ciphertext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc: Option<Enc>,
    /// Causal clock for multi-writer merge (Layer 3): `clock[author_hex] = k` means
    /// this record causally follows the first `k` records of that author (a version
    /// vector, see [`merge`]). Empty — and omitted on the wire — for single-author
    /// content (e.g. a video post) that needs no cross-writer ordering.
    #[serde(default, skip_serializing_if = "is_empty_clock")]
    pub clock: BTreeMap<String, u64>,
    /// Lamport timestamp for merge ordering (`1 + max` over `clock`); `0` — and
    /// omitted — when unused.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub lamport: u64,
}

impl Record {
    /// This record's causal clock as [`merge::Clock`] (hex author keys decoded to
    /// writer-id bytes). Malformed keys are skipped.
    pub fn causal_clock(&self) -> merge::Clock {
        self.clock
            .iter()
            .filter_map(|(k, &v)| util::bytes_from_hex::<32>(k).map(|w| (w, v)))
            .collect()
    }

    /// Bridge this record into a [`merge::Entry`] positioned at `index` in its author's
    /// feed, consuming it as the entry's opaque payload. `None` if `author` isn't a
    /// valid 32-byte hex key.
    pub fn into_entry(self, index: u64) -> Option<merge::Entry<Record>> {
        let writer = util::bytes_from_hex::<32>(&self.author)?;
        let lamport = self.lamport;
        let clock = self.causal_clock();
        Some(merge::Entry {
            writer,
            index,
            lamport,
            clock,
            payload: self,
        })
    }
}

fn is_empty_clock(m: &BTreeMap<String, u64>) -> bool {
    m.is_empty()
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Per-item encryption envelope carried in the (signed) record: the payload's
/// stream-cipher nonce, plus the content key wrapped to the channel key-encryption
/// key. The content key itself never appears in the clear.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enc {
    /// Payload stream-cipher nonce (hex, 24 bytes).
    pub n: String,
    /// Nonce used to wrap the content key (hex, 24 bytes).
    pub wn: String,
    /// Content key wrapped under the channel key-encryption-key (hex).
    pub wk: String,
}

fn is_empty_map(m: &serde_json::Map<String, serde_json::Value>) -> bool {
    m.is_empty()
}
