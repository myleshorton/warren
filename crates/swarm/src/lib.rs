//! `swarm`: a fully decentralized, self-bootstrapping peer discovery layer.
//!
//! This is the phase-0 substrate from the design doc's Part 3.3 (Option C: own
//! the swarm layer): a Kademlia DHT modeled after HyperDHT's semantics, built as
//! a **sans-IO** state machine ([`Dht`]) so it can be exhaustively verified in a
//! deterministic simulator ([`sim::Sim`]) before it ever touches a socket.
//!
//! Landed so far:
//! - [`id`]: node ids and the XOR distance metric.
//! - [`routing`]: k-bucket routing table.
//! - [`msg`]: the DHT RPC wire format (over the `wire` codec).
//! - [`dht`]: the sans-IO core with iterative Kademlia lookup.
//! - [`sim`]: the deterministic network simulator used for verification.
//!
//! Still to come (see the design doc): the ephemeral/persistent lifecycle and
//! NAT classification, the birthday-paradox hole puncher, port mapping, a real
//! UDP driver, and QUIC on top of punched paths.

pub mod dht;
pub mod id;
pub mod msg;
pub mod routing;
pub mod sim;

pub use dht::{Dht, Event, Millis, QueryId, Transmit, ALPHA, REQUEST_TIMEOUT_MS};
pub use id::{Distance, NodeId, ID_LEN};
pub use msg::{Message, Packet};
pub use routing::{Contact, RoutingTable, K};
