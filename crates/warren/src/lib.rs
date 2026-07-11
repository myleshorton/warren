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
pub mod util;
