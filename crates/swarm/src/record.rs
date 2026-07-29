//! Authenticated, bounded provider records.
//!
//! This is deliberately separate from UDP I/O: callers supply the current
//! protocol time and the observed source endpoint when admitting a record.

use crate::id::NodeId;
use crate::routing::Contact;
use crypto::{Keypair, PublicKey, Signature, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use std::collections::HashMap;
use std::net::SocketAddr;
use thiserror::Error;
use wire::{Decoder, Encoder, WireError};

const DOMAIN: &[u8] = b"warren:dht:provider-record:v1";
const CAPABILITY_LEN: usize = 32;

/// A record's requested lifetime may not exceed one hour.
pub const MAX_RECORD_LIFETIME_MS: u64 = 60 * 60 * 1000;
/// Bound the number of topics an untrusted store may retain.
pub const MAX_STORED_TOPICS: usize = 4_096;
/// Bound the number of providers held for one topic.
pub const MAX_RECORDS_PER_TOPIC: usize = 20;

/// An opaque write capability issued by the responsible store.
///
/// Its issuance and rotation protocol is intentionally kept out of this value
/// type. A record binds it cryptographically so it cannot be transplanted to a
/// different topic, owner, sequence, or expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WriteCapability([u8; CAPABILITY_LEN]);

impl WriteCapability {
    pub fn from_bytes(bytes: [u8; CAPABILITY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; CAPABILITY_LEN] {
        self.0
    }
}

#[derive(Clone, Copy)]
struct CapabilityGrant {
    topic: NodeId,
    owner: NodeId,
    expires_at: u64,
}

/// Recipient-owned, bounded authority for minting scoped write capabilities.
///
/// Capabilities are unpredictable Ed25519-signature output and are retained
/// only by their issuing store. They are valid for exactly one `(topic, owner)`
/// pair and cannot outlive the record lease. The DHT wire exchange will request
/// one before sending an authenticated announcement.
pub struct CapabilityIssuer {
    signer: Keypair,
    next_nonce: u64,
    grants: HashMap<WriteCapability, CapabilityGrant>,
}

impl CapabilityIssuer {
    pub fn new(signer: Keypair) -> Self {
        Self {
            signer,
            next_nonce: 0,
            grants: HashMap::new(),
        }
    }

    pub fn issue(&mut self, topic: NodeId, owner: NodeId, expires_at: u64) -> WriteCapability {
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1);
        let mut material = Vec::with_capacity(32 + 32 + 8);
        material.extend_from_slice(topic.as_bytes());
        material.extend_from_slice(owner.as_bytes());
        material.extend_from_slice(&nonce.to_le_bytes());
        let signature = self.signer.sign(&material).to_bytes();
        let mut token = [0u8; CAPABILITY_LEN];
        token.copy_from_slice(&signature[..CAPABILITY_LEN]);
        let capability = WriteCapability(token);
        self.grants.insert(
            capability,
            CapabilityGrant {
                topic,
                owner,
                expires_at,
            },
        );
        capability
    }

    fn authorizes(
        &self,
        capability: WriteCapability,
        topic: NodeId,
        owner: NodeId,
        record_expiry: u64,
        now: u64,
    ) -> bool {
        self.grants.get(&capability).is_some_and(|grant| {
            grant.topic == topic
                && grant.owner == owner
                && grant.expires_at >= record_expiry
                && grant.expires_at > now
        })
    }

    pub fn prune(&mut self, now: u64) {
        self.grants.retain(|_, grant| grant.expires_at > now);
    }
}

/// A signed, replay-resistant provider announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAnnouncement {
    topic: NodeId,
    owner: [u8; PUBLIC_KEY_LEN],
    sequence: u64,
    expires_at: u64,
    capability: WriteCapability,
    signature: Signature,
}

/// Why a provider record was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecordError {
    #[error("malformed provider record: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error("provider record is expired or exceeds the maximum lifetime")]
    InvalidExpiry,
    #[error("provider record sequence is stale")]
    StaleSequence,
    #[error("provider record store is full")]
    StoreFull,
    #[error("provider record lacks a valid scoped write capability")]
    UnauthorizedCapability,
}

impl SignedAnnouncement {
    pub fn sign(
        signer: &Keypair,
        topic: NodeId,
        sequence: u64,
        expires_at: u64,
        capability: WriteCapability,
    ) -> Self {
        let owner = signer.public().to_bytes();
        let signature = signer.sign(&signing_bytes(
            topic, &owner, sequence, expires_at, capability,
        ));
        Self {
            topic,
            owner,
            sequence,
            expires_at,
            capability,
            signature,
        }
    }

    pub fn topic(&self) -> NodeId {
        self.topic
    }
    pub fn owner_id(&self) -> NodeId {
        NodeId::from_bytes(crypto::hash(&self.owner))
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn capability(&self) -> WriteCapability {
        self.capability
    }

    /// Verify identity binding, signature, and the receiver's bounded time
    /// window. `now` must use the same epoch as `expires_at`.
    pub fn verify(&self, now: u64) -> Result<(), RecordError> {
        if self.expires_at <= now || self.expires_at - now > MAX_RECORD_LIFETIME_MS {
            return Err(RecordError::InvalidExpiry);
        }
        let key = PublicKey::from_bytes(&self.owner)?;
        key.verify(
            &signing_bytes(
                self.topic,
                &self.owner,
                self.sequence,
                self.expires_at,
                self.capability,
            ),
            &self.signature,
        )?;
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.raw(self.topic.as_bytes());
        enc.raw(&self.owner);
        enc.uint(self.sequence);
        enc.uint(self.expires_at);
        enc.raw(&self.capability.0);
        enc.raw(&self.signature.to_bytes());
        enc.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut dec = Decoder::new(bytes);
        let topic = NodeId::from_bytes(dec.array()?);
        let owner = dec.array()?;
        let sequence = dec.uint()?;
        let expires_at = dec.uint()?;
        let capability = WriteCapability::from_bytes(dec.array()?);
        let signature = Signature::from_bytes(dec.array::<SIGNATURE_LEN>()?);
        dec.finish()?;
        Ok(Self {
            topic,
            owner,
            sequence,
            expires_at,
            capability,
            signature,
        })
    }
}

fn signing_bytes(
    topic: NodeId,
    owner: &[u8; PUBLIC_KEY_LEN],
    sequence: u64,
    expires_at: u64,
    capability: WriteCapability,
) -> Vec<u8> {
    let mut enc = Encoder::new();
    enc.raw(DOMAIN);
    enc.raw(topic.as_bytes());
    enc.raw(owner);
    enc.uint(sequence);
    enc.uint(expires_at);
    enc.raw(&capability.0);
    enc.into_vec()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StoredAnnouncement {
    contact: Contact,
    sequence: u64,
    expires_at: u64,
}

/// A strictly bounded store keyed by `(topic, owner)`.
#[derive(Debug, Default)]
pub struct AnnouncementStore {
    topics: HashMap<NodeId, Vec<StoredAnnouncement>>,
}

impl AnnouncementStore {
    /// Verify a record and its recipient-issued capability before storing it.
    pub fn accept_authorized(
        &mut self,
        issuer: &CapabilityIssuer,
        record: &SignedAnnouncement,
        source: SocketAddr,
        now: u64,
    ) -> Result<(), RecordError> {
        record.verify(now)?;
        if !issuer.authorizes(
            record.capability,
            record.topic,
            record.owner_id(),
            record.expires_at,
            now,
        ) {
            return Err(RecordError::UnauthorizedCapability);
        }
        self.store_verified(record, source, now)
    }

    /// Verify and store a record. The endpoint is always taken from the packet
    /// source by the caller, never from signed peer-controlled bytes.
    pub fn accept(
        &mut self,
        record: &SignedAnnouncement,
        source: SocketAddr,
        now: u64,
    ) -> Result<(), RecordError> {
        record.verify(now)?;
        self.store_verified(record, source, now)
    }

    fn store_verified(
        &mut self,
        record: &SignedAnnouncement,
        source: SocketAddr,
        now: u64,
    ) -> Result<(), RecordError> {
        self.prune(now);
        let owner = record.owner_id();
        if let Some(records) = self.topics.get_mut(&record.topic) {
            if let Some(existing) = records.iter_mut().find(|entry| entry.contact.id == owner) {
                if record.sequence <= existing.sequence {
                    return Err(RecordError::StaleSequence);
                }
                *existing = StoredAnnouncement {
                    contact: Contact::new(owner, source),
                    sequence: record.sequence,
                    expires_at: record.expires_at,
                };
                return Ok(());
            }
            if records.len() >= MAX_RECORDS_PER_TOPIC {
                return Err(RecordError::StoreFull);
            }
            records.push(StoredAnnouncement {
                contact: Contact::new(owner, source),
                sequence: record.sequence,
                expires_at: record.expires_at,
            });
            return Ok(());
        }
        if self.topics.len() >= MAX_STORED_TOPICS {
            return Err(RecordError::StoreFull);
        }
        self.topics.insert(
            record.topic,
            vec![StoredAnnouncement {
                contact: Contact::new(owner, source),
                sequence: record.sequence,
                expires_at: record.expires_at,
            }],
        );
        Ok(())
    }

    pub fn contacts(&self, topic: NodeId) -> Vec<Contact> {
        self.topics
            .get(&topic)
            .into_iter()
            .flatten()
            .map(|entry| entry.contact)
            .collect()
    }

    pub fn prune(&mut self, now: u64) {
        self.topics.retain(|_, records| {
            records.retain(|record| record.expires_at > now);
            !records.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn key(n: u8) -> Keypair {
        Keypair::from_seed(&[n; 32])
    }
    fn topic(n: u8) -> NodeId {
        NodeId::from_bytes([n; 32])
    }
    fn cap(n: u8) -> WriteCapability {
        WriteCapability::from_bytes([n; 32])
    }
    fn source(port: u16) -> SocketAddr {
        format!("192.0.2.1:{port}").parse().unwrap()
    }

    #[test]
    fn signed_record_round_trips_and_verifies() {
        let record = SignedAnnouncement::sign(&key(1), topic(2), 3, 1_000, cap(4));
        let decoded = SignedAnnouncement::decode(&record.encode()).unwrap();
        assert_eq!(decoded, record);
        decoded.verify(999).unwrap();
    }

    #[test]
    fn tampering_and_excessive_lifetimes_are_rejected() {
        let record = SignedAnnouncement::sign(&key(1), topic(2), 3, 1_000, cap(4));
        let mut bytes = record.encode();
        bytes[32] ^= 1;
        assert!(SignedAnnouncement::decode(&bytes)
            .unwrap()
            .verify(999)
            .is_err());
        let long_lived =
            SignedAnnouncement::sign(&key(1), topic(2), 4, MAX_RECORD_LIFETIME_MS + 1, cap(4));
        assert_eq!(long_lived.verify(0), Err(RecordError::InvalidExpiry));
    }

    #[test]
    fn store_rejects_replay_and_uses_observed_source() {
        let mut store = AnnouncementStore::default();
        let first = SignedAnnouncement::sign(&key(1), topic(2), 1, 1_000, cap(4));
        store.accept(&first, source(1000), 999).unwrap();
        assert_eq!(
            store.accept(&first, source(2000), 999),
            Err(RecordError::StaleSequence)
        );
        let fresh = SignedAnnouncement::sign(&key(1), topic(2), 2, 1_000, cap(4));
        store.accept(&fresh, source(2000), 999).unwrap();
        assert_eq!(
            store.contacts(topic(2)),
            vec![Contact::new(fresh.owner_id(), source(2000))]
        );
    }

    #[test]
    fn capability_is_scoped_to_one_owner_topic_and_lease() {
        let issuer_key = key(9);
        let mut issuer = CapabilityIssuer::new(issuer_key);
        let mut store = AnnouncementStore::default();
        let grant = issuer.issue(
            topic(2),
            NodeId::from_bytes(crypto::hash(key(1).public().as_bytes())),
            1_000,
        );
        let allowed = SignedAnnouncement::sign(&key(1), topic(2), 1, 1_000, grant);
        store
            .accept_authorized(&issuer, &allowed, source(1000), 999)
            .unwrap();

        let wrong_topic = SignedAnnouncement::sign(&key(1), topic(3), 1, 1_000, grant);
        assert_eq!(
            store.accept_authorized(&issuer, &wrong_topic, source(1000), 999),
            Err(RecordError::UnauthorizedCapability)
        );
        let wrong_owner = SignedAnnouncement::sign(&key(2), topic(2), 1, 1_000, grant);
        assert_eq!(
            store.accept_authorized(&issuer, &wrong_owner, source(1000), 999),
            Err(RecordError::UnauthorizedCapability)
        );
    }
}
