//! The general signed-record envelope + its encryption metadata.
//!
//! A record is one block in a creator's signed [`feed`](feed) log. It is
//! deliberately content-agnostic: `content_type` says what the payload is, a small
//! payload can ride inline in `body`, a large one is a content-addressed `blob`
//! attachment, and `meta` carries whatever app-specific fields an application needs
//! (a video title, a chat reply-to, …). `enc` is present when the payload is
//! encrypted. Murmur's video post is one specialization; a chat message is another.

use serde::{Deserialize, Serialize};

/// A signed feed record, content-agnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
