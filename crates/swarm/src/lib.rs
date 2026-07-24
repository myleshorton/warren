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
//! - [`nat`]: NAT self-classification from address samples.
//! - [`natbox`]: packet-level NAT model (mapping + filtering) for one endpoint.
//! - [`punch`]: hole-punch strategy, the birthday model, and a packet-level punch.
//! - [`sim`]: the deterministic network simulator used for verification.
//!
//! Still to come (see the design doc): coordinating a punch over the live DHT
//! (relay-brokered address exchange), port mapping, a real UDP driver, and QUIC
//! on punched paths.

pub mod dht;
pub mod id;
pub mod lan;
pub mod msg;
pub mod nat;
pub mod natbox;
pub mod punch;
pub mod routing;
pub mod sim;

pub use dht::{ConnectOutcome, Dht, Event, Millis, QueryId, Transmit, ALPHA, REQUEST_TIMEOUT_MS};
pub use id::{Distance, NodeId, ID_LEN};
pub use msg::{Message, Packet};
pub use nat::{Firewall, NatSampler};
pub use natbox::{NatBox, SocketId};
pub use punch::{attempt_punch, packet_punch, plan, Outcome, PunchParams, Strategy};
pub use routing::{Contact, RoutingTable, K};
