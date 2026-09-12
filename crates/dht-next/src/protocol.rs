//! Versioned, bounded, signed datagrams for the experimental DHT.
use crypto::{Keypair, PublicKey, Signature};
use routing_types::{Contact, NodeId};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use wire::{Decoder, Encoder};

pub const MAX_PACKET: usize = 1200;
pub const MAX_CONTACTS: usize = 8;
pub const MAX_RECORDS: usize = 2;
pub const MAX_VALUE_CONTACTS: usize = 4;
pub const MAX_SIGNAL: usize = 256;
pub const MAX_SEALED_SIGNAL: usize = MAX_SIGNAL + 48;
const MAGIC: &[u8] = b"WRD2\x06";

pub fn node_id(key: PublicKey) -> NodeId {
    NodeId::from_bytes(crypto::hash(key.as_bytes()))
}

/// A provider authorizes one DHT node to serve as its rendezvous coordinator.
/// Times are Unix seconds supplied by the caller; no clock is read here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub provider: PublicKey,
    pub topic: NodeId,
    pub signaling_key: [u8; 32],
    pub coordinator: Contact,
    pub expires: u64,
    pub signature: Signature,
}

impl Record {
    pub fn sign(
        key: &Keypair,
        topic: NodeId,
        coordinator: Contact,
        expires: u64,
        signaling_key: [u8; 32],
    ) -> Self {
        let mut record = Self {
            provider: key.public(),
            topic,
            signaling_key,
            coordinator,
            expires,
            signature: Signature::from_bytes([0; 64]),
        };
        record.signature = key.sign(&record.signing_bytes());
        record
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.raw(b"warren:dht-next:record:v2")
            .raw(self.provider.as_bytes())
            .raw(self.topic.as_bytes())
            .raw(&self.signaling_key);
        encode_contact(&mut e, self.coordinator);
        e.u64_le(self.expires);
        e.into_vec()
    }

    pub fn verify(&self, now: u64) -> bool {
        self.expires > now
            && self.expires <= now.saturating_add(LEASE_SECS)
            && self
                .provider
                .verify_strict(&self.signing_bytes(), &self.signature)
                .is_ok()
    }
}

pub const LEASE_SECS: u64 = 300;
pub const SIGNAL_SECS: u64 = 20;

/// End-to-end signed ciphertext. Routing metadata remains visible to coordinators.
/// Application plaintext is emitted separately as `ReceivedSignal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signal {
    pub author: PublicKey,
    pub recipient: NodeId,
    pub session: [u8; 32],
    pub expires: u64,
    pub answer: bool,
    pub payload: Vec<u8>,
    pub signature: Signature,
}

impl Signal {
    pub(crate) fn sign(
        key: &Keypair,
        recipient: NodeId,
        session: [u8; 32],
        expires: u64,
        answer: bool,
        payload: Vec<u8>,
    ) -> Self {
        let mut s = Self {
            author: key.public(),
            recipient,
            session,
            expires,
            answer,
            payload,
            signature: Signature::from_bytes([0; 64]),
        };
        s.signature = key.sign(&s.signing_bytes());
        s
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.raw(b"warren:dht-next:signal:v2")
            .raw(self.author.as_bytes())
            .raw(self.recipient.as_bytes())
            .raw(&self.session)
            .u64_le(self.expires)
            .u8(u8::from(self.answer))
            .bytes(&self.payload);
        e.into_vec()
    }

    pub fn verify(&self, now: u64) -> bool {
        (48..=MAX_SEALED_SIGNAL).contains(&self.payload.len())
            && self.expires > now
            && self.expires <= now.saturating_add(SIGNAL_SECS)
            && self
                .author
                .verify_strict(&self.signing_bytes(), &self.signature)
                .is_ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    Probe,
    Reflect,
    Reflected(SocketAddr),
    PutValue {
        value: crate::Value,
        cas: Option<u64>,
    },
    GetValue(NodeId),
    ValueResult(Option<crate::Value>),
    ValueStored(bool),
    Find(NodeId),
    FindValue(NodeId),
    ValueNodes {
        contacts: Vec<Contact>,
        value: Option<crate::Value>,
    },
    GetProviders {
        topic: NodeId,
        after: Option<NodeId>,
    },
    ProviderPage {
        records: Vec<Record>,
        next: Option<NodeId>,
    },
    Register(Record),
    Offer {
        record: Record,
        signal: Box<Signal>,
    },
    Forward(Signal),
    Answer(Signal),
    Challenge,
    Ack,
    Nodes {
        contacts: Vec<Contact>,
        records: Vec<Record>,
    },
}

impl Body {
    pub(crate) fn read_only(&self) -> bool {
        matches!(
            self,
            Self::Probe
                | Self::Reflect
                | Self::Find(_)
                | Self::GetProviders { .. }
                | Self::GetValue(_)
                | Self::FindValue(_)
        )
    }

    pub fn response(&self) -> bool {
        matches!(
            self,
            Self::Reflected(_)
                | Self::Challenge
                | Self::Ack
                | Self::Nodes { .. }
                | Self::ProviderPage { .. }
                | Self::ValueResult(_)
                | Self::ValueStored(_)
                | Self::ValueNodes { .. }
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Packet {
    pub key: PublicKey,
    pub destination: NodeId,
    pub server: bool,
    pub nonce: [u8; 32],
    pub epoch: u64,
    pub cookie: [u8; 32],
    pub body: Body,
    pub exchange: Vec<u8>,
}

impl Packet {
    pub fn encode(&self, key: &Keypair) -> Vec<u8> {
        let mut e = Encoder::new();
        e.raw(MAGIC)
            .raw(self.key.as_bytes())
            .raw(self.destination.as_bytes())
            .u8(u8::from(self.server))
            .raw(&self.nonce)
            .u64_le(self.epoch)
            .raw(&self.cookie);
        e.u8(self.exchange.len() as u8).raw(&self.exchange);
        self.encode_body(&mut e);
        let signature = {
            #[cfg(feature = "diagnostics")]
            let _span = crate::diagnostics::span(crate::diagnostics::Region::Sign);
            key.sign(e.as_slice())
        };
        e.raw(&signature.to_bytes());
        e.into_vec()
    }

    pub(crate) fn plausible(bytes: &[u8]) -> bool {
        (208..=MAX_PACKET).contains(&bytes.len()) && bytes.starts_with(MAGIC)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_PACKET || bytes.len() < 64 {
            return None;
        }
        let (content, signature) = bytes.split_at(bytes.len() - 64);
        let mut d = Decoder::canonical(content);
        if d.raw(MAGIC.len()).ok()? != MAGIC {
            return None;
        }
        let key = PublicKey::from_bytes(&d.array().ok()?).ok()?;
        let destination = NodeId::from_bytes(d.array().ok()?);
        let server = boolean(&mut d)?;
        let nonce = d.array().ok()?;
        let epoch = d.u64_le().ok()?;
        let cookie = d.array().ok()?;
        let count = d.u8().ok()? as usize;
        if !matches!(count, 0 | 32 | 48) {
            return None;
        }
        let exchange = d.raw(count).ok()?.to_vec();
        let body = Self::decode_body(&mut d)?;
        d.finish().ok()?;
        {
            #[cfg(feature = "diagnostics")]
            let _span = crate::diagnostics::span(crate::diagnostics::Region::Verify);
            key.verify_strict(content, &Signature::from_bytes(signature.try_into().ok()?))
                .ok()?;
        }
        Some(Self {
            key,
            destination,
            server,
            nonce,
            epoch,
            cookie,
            body,
            exchange,
        })
    }

    fn encode_body(&self, e: &mut Encoder) {
        match &self.body {
            Body::Reflect => {
                e.u8(17);
            }
            Body::Reflected(address) => {
                e.u8(18);
                encode_addr(e, *address);
            }

            Body::PutValue { value, cas } => {
                e.u8(11);
                crate::value::encode(e, value);
                match cas {
                    None => {
                        e.u8(0);
                    }
                    Some(sequence) => {
                        e.u8(1).u64_le(*sequence);
                    }
                }
            }
            Body::GetValue(key) => {
                e.u8(12).raw(key.as_bytes());
            }
            Body::ValueResult(value) => {
                e.u8(13);
                match value {
                    None => {
                        e.u8(0);
                    }
                    Some(value) => {
                        e.u8(1);
                        crate::value::encode(e, value);
                    }
                }
            }
            Body::FindValue(key) => {
                e.u8(15).raw(key.as_bytes());
            }
            Body::ValueNodes { contacts, value } => {
                e.u8(16).u8(u8::from(value.is_some()));
                if let Some(value) = value {
                    crate::value::encode(e, value);
                }
                e.u8(contacts.len() as u8);
                for contact in contacts {
                    encode_contact(e, *contact);
                }
            }
            Body::ValueStored(stored) => {
                e.u8(14).u8(u8::from(*stored));
            }
            Body::Probe => {
                e.u8(0);
            }
            Body::Find(target) => {
                e.u8(1).raw(target.as_bytes());
            }
            Body::GetProviders { topic, after } => {
                e.u8(9).raw(topic.as_bytes());
                encode_cursor(e, *after);
            }
            Body::ProviderPage { records, next } => {
                e.u8(10).u8(records.len() as u8);
                for record in records {
                    encode_record(e, record);
                }
                encode_cursor(e, *next);
            }
            Body::Register(r) => {
                e.u8(2);
                encode_record(e, r);
            }
            Body::Offer { record, signal } => {
                e.u8(3);
                encode_record(e, record);
                encode_signal(e, signal);
            }
            Body::Forward(s) => {
                e.u8(4);
                encode_signal(e, s);
            }
            Body::Answer(s) => {
                e.u8(5);
                encode_signal(e, s);
            }
            Body::Challenge => {
                e.u8(6);
            }
            Body::Ack => {
                e.u8(7);
            }
            Body::Nodes { contacts, records } => {
                e.u8(8).u8(contacts.len() as u8);
                for c in contacts {
                    encode_contact(e, *c);
                }
                e.u8(records.len() as u8);
                for r in records {
                    encode_record(e, r);
                }
            }
        }
    }

    fn decode_body(d: &mut Decoder<'_>) -> Option<Body> {
        Some(match d.u8().ok()? {
            0 => Body::Probe,
            17 => Body::Reflect,
            18 => Body::Reflected(decode_addr(d)?),
            1 => Body::Find(NodeId::from_bytes(d.array().ok()?)),
            11 => {
                let value = crate::value::decode(d)?;
                let cas = match d.u8().ok()? {
                    0 => None,
                    1 => Some(d.u64_le().ok()?),
                    _ => return None,
                };
                Body::PutValue { value, cas }
            }
            12 => Body::GetValue(NodeId::from_bytes(d.array().ok()?)),
            13 => Body::ValueResult(match d.u8().ok()? {
                0 => None,
                1 => Some(crate::value::decode(d)?),
                _ => return None,
            }),
            14 => Body::ValueStored(boolean(d)?),
            15 => Body::FindValue(NodeId::from_bytes(d.array().ok()?)),
            16 => {
                let value = if boolean(d)? {
                    Some(crate::value::decode(d)?)
                } else {
                    None
                };
                let count = d.u8().ok()? as usize;
                let limit = if value.is_some() {
                    MAX_VALUE_CONTACTS
                } else {
                    MAX_CONTACTS
                };
                if count > limit {
                    return None;
                }
                let mut contacts = Vec::with_capacity(count);
                for _ in 0..count {
                    contacts.push(decode_contact(d)?);
                }
                Body::ValueNodes { contacts, value }
            }
            9 => Body::GetProviders {
                topic: NodeId::from_bytes(d.array().ok()?),
                after: decode_cursor(d)?,
            },
            10 => {
                let count = d.u8().ok()? as usize;
                if count > MAX_RECORDS {
                    return None;
                }
                let mut records = Vec::with_capacity(count);
                for _ in 0..count {
                    records.push(decode_record(d)?);
                }
                Body::ProviderPage {
                    records,
                    next: decode_cursor(d)?,
                }
            }
            2 => Body::Register(decode_record(d)?),
            3 => Body::Offer {
                record: decode_record(d)?,
                signal: Box::new(decode_signal(d)?),
            },
            4 => Body::Forward(decode_signal(d)?),
            5 => Body::Answer(decode_signal(d)?),
            6 => Body::Challenge,
            7 => Body::Ack,
            8 => {
                let count = d.u8().ok()? as usize;
                if count > MAX_CONTACTS {
                    return None;
                }
                let mut contacts = Vec::with_capacity(count);
                for _ in 0..count {
                    contacts.push(decode_contact(d)?);
                }
                let count = d.u8().ok()? as usize;
                if count > MAX_RECORDS {
                    return None;
                }
                let mut records = Vec::with_capacity(count);
                for _ in 0..count {
                    records.push(decode_record(d)?);
                }
                Body::Nodes { contacts, records }
            }
            _ => return None,
        })
    }

    pub fn compact(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(u8::from(self.server))
            .raw(&self.nonce)
            .u64_le(self.epoch)
            .raw(&self.cookie);
        self.encode_body(&mut e);
        e.into_vec()
    }

    pub fn from_compact(bytes: &[u8], key: PublicKey, destination: NodeId) -> Option<Self> {
        let mut d = Decoder::canonical(bytes);
        let packet = Self {
            key,
            destination,
            server: boolean(&mut d)?,
            nonce: d.array().ok()?,
            epoch: d.u64_le().ok()?,
            cookie: d.array().ok()?,
            body: Self::decode_body(&mut d)?,
            exchange: Vec::new(),
        };
        d.finish().ok()?;
        Some(packet)
    }
}

fn boolean(d: &mut Decoder<'_>) -> Option<bool> {
    match d.u8().ok()? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

pub(crate) fn encode_addr(e: &mut Encoder, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            e.u8(4).raw(&ip.octets());
        }
        IpAddr::V6(ip) => {
            e.u8(6).raw(&ip.octets());
        }
    }
    e.u16_le(addr.port());
}

fn decode_addr(d: &mut Decoder<'_>) -> Option<SocketAddr> {
    let ip = match d.u8().ok()? {
        4 => IpAddr::V4(Ipv4Addr::from(d.array::<4>().ok()?)),
        6 => IpAddr::V6(Ipv6Addr::from(d.array::<16>().ok()?)),
        _ => return None,
    };
    let addr = SocketAddr::new(ip, d.u16_le().ok()?);
    if addr.port() == 0 || ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    Some(addr)
}

fn encode_cursor(e: &mut Encoder, cursor: Option<NodeId>) {
    match cursor {
        None => {
            e.u8(0);
        }
        Some(id) => {
            e.u8(1).raw(id.as_bytes());
        }
    }
}
fn decode_cursor(d: &mut wire::Decoder<'_>) -> Option<Option<NodeId>> {
    match d.u8().ok()? {
        0 => Some(None),
        1 => Some(Some(NodeId::from_bytes(d.array().ok()?))),
        _ => None,
    }
}

fn encode_contact(e: &mut Encoder, c: Contact) {
    e.raw(c.id.as_bytes());
    encode_addr(e, c.addr);
}
fn decode_contact(d: &mut Decoder<'_>) -> Option<Contact> {
    Some(Contact::new(
        NodeId::from_bytes(d.array().ok()?),
        decode_addr(d)?,
    ))
}
fn encode_record(e: &mut Encoder, r: &Record) {
    e.raw(r.provider.as_bytes())
        .raw(r.topic.as_bytes())
        .raw(&r.signaling_key);
    encode_contact(e, r.coordinator);
    e.u64_le(r.expires).raw(&r.signature.to_bytes());
}
fn decode_record(d: &mut Decoder<'_>) -> Option<Record> {
    Some(Record {
        provider: PublicKey::from_bytes(&d.array().ok()?).ok()?,
        topic: NodeId::from_bytes(d.array().ok()?),
        signaling_key: d.array().ok()?,
        coordinator: decode_contact(d)?,
        expires: d.u64_le().ok()?,
        signature: Signature::from_bytes(d.array().ok()?),
    })
}
fn encode_signal(e: &mut Encoder, s: &Signal) {
    e.raw(s.author.as_bytes())
        .raw(s.recipient.as_bytes())
        .raw(&s.session)
        .u64_le(s.expires)
        .u8(u8::from(s.answer))
        .bytes(&s.payload)
        .raw(&s.signature.to_bytes());
}
fn decode_signal(d: &mut Decoder<'_>) -> Option<Signal> {
    let author = PublicKey::from_bytes(&d.array().ok()?).ok()?;
    let recipient = NodeId::from_bytes(d.array().ok()?);
    let session = d.array().ok()?;
    let expires = d.u64_le().ok()?;
    let answer = boolean(d)?;
    let payload = d.bytes().ok()?;
    if !(48..=MAX_SEALED_SIGNAL).contains(&payload.len()) {
        return None;
    }
    Some(Signal {
        author,
        recipient,
        session,
        expires,
        answer,
        payload: payload.to_vec(),
        signature: Signature::from_bytes(d.array().ok()?),
    })
}
