//! PSK community channels: a shared secret gates a rotating discovery topic.
//!
//! An open "see everyone" topic would be trivially crawlable and would defeat the
//! point of blinded topics, so discovery is gated by a shared channel key (the
//! "invite"). Members announce under `H(domain ‖ psk ‖ epoch)`, which rotates
//! every [`EPOCH_LEN_SECS`] and is opaque to anyone without the key. A member
//! looks up the current (and previous) epoch's topic to find who's online.
//!
//! `domain` is supplied by the application so two apps that happen to share a PSK
//! derive different topics and never collide. Pass a stable, versioned label such
//! as `b"myapp:channel:v1"`.

use swarm::NodeId;

/// How long a discovery epoch lasts. Members announce under the current and next
/// epoch's topic, and viewers look up the current and previous, so a lookup near
/// a rotation boundary still finds peers.
pub const EPOCH_LEN_SECS: u64 = 3600;

/// The current epoch number (wall clock).
pub fn current_epoch() -> u64 {
    crypto::epoch(crate::util::now_secs(), EPOCH_LEN_SECS)
}

/// The discovery topic for a channel `psk` at a given `epoch`, namespaced by the
/// application's `domain`. Derived from the PSK alone (not any member's key), so
/// every member computes the same topic and discovers each other — while it stays
/// opaque and rotating to outsiders.
pub fn channel_topic(domain: &[u8], psk: &[u8], epoch: u64) -> NodeId {
    let epoch_le = epoch.to_le_bytes();
    NodeId::from_bytes(crypto::hash_parts(&[domain, psk, &epoch_le]))
}

/// The content topic for a blob id: every peer holding that blob (the origin, any
/// mirrors, other seeders) announces under it, so a downloader can `lookup` it to
/// find **all** sources and swarm the content from several at once — not just the
/// one member whose feed pointed at it. Namespaced by the application's `domain`
/// and derived from the (already public) blob id, not the channel key.
pub fn content_topic(domain: &[u8], blob_id: &[u8]) -> NodeId {
    NodeId::from_bytes(crypto::hash_parts(&[domain, blob_id]))
}

/// The discovery topic for a feed, keyed by its owner's public key (`feed_key`):
/// the author and every mirror holding a replica of that feed announce under it,
/// so a subscriber can `lookup` all of them and live-tail from any — the feed
/// analogue of [`content_topic`], and what makes swarm-failover subscription +
/// blind-mirror store-and-forward possible. Namespaced by the app's `domain`.
pub fn feed_topic(domain: &[u8], feed_key: &[u8]) -> NodeId {
    NodeId::from_bytes(crypto::hash_parts(&[domain, feed_key]))
}
