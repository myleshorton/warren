//! Warren — a serverless peer-to-peer application substrate.
//!
//! The low-level Warren crates (`driver`, `swarm`, `transfer`, `feed`, `blob`,
//! `crypto`, `portmap`) give you connectivity, discovery, and verified data sync.
//! `warren` composes them into the app-agnostic layer an application sits on: PSK
//! channel membership, blinded discovery topics, shareable invites, a general
//! signed record envelope, swarm content discovery, and blind mirroring — none of
//! it specific to any one kind of content.
//!
//! Murmur (a short-video app) is one specialization; chat, file sync, and signed
//! data feeds are others. Anything specific to a single app (video titles, a
//! moderation model, the UniFFI bindings) lives in the app, not here.

pub mod channel;
pub mod invite;
pub mod merge;
pub mod protocol;
pub mod record;
pub mod session;
pub mod store;
pub mod util;

use serde::{Deserialize, Serialize};

/// A bootstrap peer to seed the DHT: a node id (hex) and the UDP `host:port` to
/// reach it at. The app's binding layer wraps this in whatever FFI type it needs.
/// Serializable so it doubles as the on-disk bootstrap-cache entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub node_id: String,
    pub addr: String,
}
