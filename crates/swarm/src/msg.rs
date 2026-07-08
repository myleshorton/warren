//! DHT RPC wire format.
//!
//! Every packet carries the sender's [`NodeId`] and a request id (`rid`) that a
//! response echoes, so a requester can match replies to in-flight requests.
//! Bodies are one of a small set of message kinds. Serialization goes through
//! the [`wire`] codec.

use crate::id::{NodeId, ID_LEN};
use crate::routing::Contact;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use wire::{Decoder, Encoder, WireError};

const KIND_PING: u8 = 1;
const KIND_PONG: u8 = 2;
const KIND_FIND_NODE: u8 = 3;
const KIND_NODES: u8 = 4;

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
    /// Reply to [`Message::FindNode`] with closest known contacts.
    Nodes { contacts: Vec<Contact> },
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
            Message::Nodes { contacts } => {
                enc.u8(KIND_NODES);
                enc.uint(contacts.len() as u64);
                for c in contacts {
                    enc.raw(c.id.as_bytes());
                    encode_addr(&mut enc, &c.addr);
                }
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
                let n = dec.uint()?;
                // Each contact is at least 32 + 1 + 2 bytes; reject counts that
                // cannot possibly fit so a bad length can't drive a huge alloc.
                if n > dec.remaining() as u64 {
                    return Err(MsgError::Malformed("contact count exceeds buffer"));
                }
                let mut contacts = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let id = NodeId::from_bytes(dec.array::<ID_LEN>()?);
                    let addr = decode_addr(&mut dec)?;
                    contacts.push(Contact::new(id, addr));
                }
                Message::Nodes { contacts }
            }
            _ => return Err(MsgError::Malformed("unknown message kind")),
        };
        dec.finish()?;
        Ok(Packet { sender, rid, msg })
    }
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

    #[test]
    fn nodes_roundtrip_both_families() {
        let contacts = vec![
            Contact::new(
                id(10),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5000)),
            ),
            Contact::new(
                id(11),
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 6000, 0, 0)),
            ),
        ];
        roundtrip(&Packet {
            sender: id(4),
            rid: 100,
            msg: Message::Nodes { contacts },
        });
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
