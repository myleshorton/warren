//! DHT RPC wire format.
//!
//! Every packet carries the sender's [`NodeId`] and a request id (`rid`) that a
//! response echoes, so a requester can match replies to in-flight requests.
//! Bodies are one of a small set of message kinds. Serialization goes through
//! the [`wire`] codec.

use crate::id::{NodeId, ID_LEN};
use crate::nat::Firewall;
use crate::routing::Contact;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use wire::{Decoder, Encoder, WireError};

const KIND_PING: u8 = 1;
const KIND_PONG: u8 = 2;
const KIND_FIND_NODE: u8 = 3;
const KIND_NODES: u8 = 4;
const KIND_ANNOUNCE: u8 = 5;
const KIND_SIGNAL: u8 = 7;

const ADDR_V4: u8 = 4;
const ADDR_V6: u8 = 6;

/// Errors decoding a packet.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MsgError {
    /// A field was malformed or a tag was unrecognized.
    #[error("malformed packet: {0}")]
    Malformed(&'static str),
    /// The underlying byte codec rejected the buffer.
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// The body of a DHT packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Liveness probe.
    Ping,
    /// Reply to [`Message::Ping`], echoing the source address the responder saw.
    Pong { observed: SocketAddr },
    /// Request the closest known nodes to `target`.
    FindNode { target: NodeId },
    /// Reply to [`Message::FindNode`]: the closest known contacts, plus any
    /// announce records the responder holds for `target` (empty if none).
    Nodes {
        /// Closer nodes toward the queried target.
        contacts: Vec<Contact>,
        /// Peers that announced themselves under the queried target.
        peers: Vec<Contact>,
    },
    /// Ask the recipient to store the sender as an announcer under `topic`.
    /// One-way (best-effort); the announcer does not wait for confirmation.
    Announce { topic: NodeId },
    /// Coordinate a hole punch: relayed initiator↔target through a coordinator
    /// that holds the target's announce record.
    Signal {
        /// The peer being connected to.
        target: NodeId,
        /// The peer initiating the connection.
        initiator: NodeId,
        /// The initiator's address, as observed and filled in by the coordinator.
        initiator_addr: SocketAddr,
        /// The sender's firewall type (initiator's on a request, target's on a reply).
        nat: Firewall,
        /// False for an initiator→target request, true for a target→initiator reply.
        is_reply: bool,
    },
}

/// A full DHT packet: sender identity, request id, and a message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Id of the node that sent this packet.
    pub sender: NodeId,
    /// Request id; a response repeats the id of the request it answers.
    pub rid: u64,
    /// The message body.
    pub msg: Message,
}

impl Packet {
    /// Encode the packet to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.raw(self.sender.as_bytes());
        enc.uint(self.rid);
        match &self.msg {
            Message::Ping => {
                enc.u8(KIND_PING);
            }
            Message::Pong { observed } => {
                enc.u8(KIND_PONG);
                encode_addr(&mut enc, observed);
            }
            Message::FindNode { target } => {
                enc.u8(KIND_FIND_NODE);
                enc.raw(target.as_bytes());
            }
            Message::Nodes { contacts, peers } => {
                enc.u8(KIND_NODES);
                encode_contacts(&mut enc, contacts);
                encode_contacts(&mut enc, peers);
            }
            Message::Announce { topic } => {
                enc.u8(KIND_ANNOUNCE);
                enc.raw(topic.as_bytes());
            }
            Message::Signal {
                target,
                initiator,
                initiator_addr,
                nat,
                is_reply,
            } => {
                enc.u8(KIND_SIGNAL);
                enc.raw(target.as_bytes());
                enc.raw(initiator.as_bytes());
                encode_addr(&mut enc, initiator_addr);
                enc.u8(nat.as_u8());
                enc.u8(u8::from(*is_reply));
            }
        }
        enc.into_vec()
    }

    /// Decode a packet from bytes.
    pub fn decode(buf: &[u8]) -> Result<Packet, MsgError> {
        let mut dec = Decoder::new(buf);
        let sender = NodeId::from_bytes(dec.array::<ID_LEN>()?);
        let rid = dec.uint()?;
        let kind = dec.u8()?;
        let msg = match kind {
            KIND_PING => Message::Ping,
            KIND_PONG => Message::Pong {
                observed: decode_addr(&mut dec)?,
            },
            KIND_FIND_NODE => {
                let target = NodeId::from_bytes(dec.array::<ID_LEN>()?);
                Message::FindNode { target }
            }
            KIND_NODES => {
                let contacts = decode_contacts(&mut dec)?;
                let peers = decode_contacts(&mut dec)?;
                Message::Nodes { contacts, peers }
            }
            KIND_ANNOUNCE => {
                let topic = NodeId::from_bytes(dec.array::<ID_LEN>()?);
                Message::Announce { topic }
            }
            KIND_SIGNAL => {
                let target = NodeId::from_bytes(dec.array::<ID_LEN>()?);
                let initiator = NodeId::from_bytes(dec.array::<ID_LEN>()?);
                let initiator_addr = decode_addr(&mut dec)?;
                let nat = Firewall::from_u8(dec.u8()?)
                    .ok_or(MsgError::Malformed("unknown firewall tag"))?;
                let is_reply = dec.u8()? != 0;
                Message::Signal {
                    target,
                    initiator,
                    initiator_addr,
                    nat,
                    is_reply,
                }
            }
            _ => return Err(MsgError::Malformed("unknown message kind")),
        };
        dec.finish()?;
        Ok(Packet { sender, rid, msg })
    }
}

fn encode_contacts(enc: &mut Encoder, contacts: &[Contact]) {
    enc.uint(contacts.len() as u64);
    for c in contacts {
        enc.raw(c.id.as_bytes());
        encode_addr(enc, &c.addr);
    }
}

fn decode_contacts<'a>(dec: &mut Decoder<'a>) -> Result<Vec<Contact>, MsgError> {
    // A contact is at minimum an id + an address-family tag + a v4 address:
    // 32 + 1 + (4 + 2) bytes. Bounding the count by this (not by raw remaining
    // bytes) stops a crafted length from forcing an allocation ~40x the buffer.
    const MIN_CONTACT_BYTES: u64 = ID_LEN as u64 + 1 + 4 + 2;
    let n = dec.uint()?;
    if n > dec.remaining() as u64 / MIN_CONTACT_BYTES {
        return Err(MsgError::Malformed("contact count exceeds buffer"));
    }
    let mut contacts = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let id = NodeId::from_bytes(dec.array::<ID_LEN>()?);
        let addr = decode_addr(dec)?;
        contacts.push(Contact::new(id, addr));
    }
    Ok(contacts)
}

fn encode_addr(enc: &mut Encoder, addr: &SocketAddr) {
    match addr {
        SocketAddr::V4(a) => {
            enc.u8(ADDR_V4);
            enc.raw(&a.ip().octets());
            enc.u16_le(a.port());
        }
        SocketAddr::V6(a) => {
            enc.u8(ADDR_V6);
            enc.raw(&a.ip().octets());
            enc.u16_le(a.port());
        }
    }
}

fn decode_addr(dec: &mut Decoder) -> Result<SocketAddr, MsgError> {
    match dec.u8()? {
        ADDR_V4 => {
            let octets = dec.array::<4>()?;
            let port = dec.u16_le()?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        ADDR_V6 => {
            let octets = dec.array::<16>()?;
            let port = dec.u16_le()?;
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(MsgError::Malformed("unknown address family")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn id(b: u8) -> NodeId {
        NodeId::from_bytes([b; ID_LEN])
    }

    fn roundtrip(p: &Packet) {
        let bytes = p.encode();
        let back = Packet::decode(&bytes).unwrap();
        assert_eq!(*p, back);
    }

    #[test]
    fn ping_pong_roundtrip() {
        roundtrip(&Packet {
            sender: id(1),
            rid: 7,
            msg: Message::Ping,
        });
        roundtrip(&Packet {
            sender: id(2),
            rid: 8,
            msg: Message::Pong {
                observed: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 42)),
            },
        });
    }

    #[test]
    fn find_node_roundtrip() {
        roundtrip(&Packet {
            sender: id(3),
            rid: 42,
            msg: Message::FindNode { target: id(9) },
        });
    }

    fn addr4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port))
    }

    #[test]
    fn nodes_roundtrip_both_families() {
        let contacts = vec![
            Contact::new(id(10), addr4(5000)),
            Contact::new(
                id(11),
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 6000, 0, 0)),
            ),
        ];
        let peers = vec![Contact::new(id(12), addr4(7000))];
        roundtrip(&Packet {
            sender: id(4),
            rid: 100,
            msg: Message::Nodes { contacts, peers },
        });
        // Empty peers list is the common case and must round-trip too.
        roundtrip(&Packet {
            sender: id(4),
            rid: 101,
            msg: Message::Nodes {
                contacts: vec![Contact::new(id(10), addr4(5000))],
                peers: vec![],
            },
        });
    }

    #[test]
    fn announce_roundtrip() {
        roundtrip(&Packet {
            sender: id(5),
            rid: 1,
            msg: Message::Announce { topic: id(99) },
        });
    }

    #[test]
    fn signal_roundtrip() {
        for (nat, is_reply) in [
            (Firewall::Open, false),
            (Firewall::Consistent, true),
            (Firewall::Random, false),
        ] {
            roundtrip(&Packet {
                sender: id(6),
                rid: 3,
                msg: Message::Signal {
                    target: id(20),
                    initiator: id(21),
                    initiator_addr: addr4(9000),
                    nat,
                    is_reply,
                },
            });
        }
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let mut enc = Encoder::new();
        enc.raw(id(1).as_bytes());
        enc.uint(1);
        enc.u8(99);
        assert_eq!(
            Packet::decode(&enc.into_vec()),
            Err(MsgError::Malformed("unknown message kind"))
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = Packet {
            sender: id(1),
            rid: 1,
            msg: Message::Ping,
        }
        .encode();
        bytes.push(0xff);
        assert!(matches!(
            Packet::decode(&bytes),
            Err(MsgError::Wire(WireError::TrailingBytes(1)))
        ));
    }
}
