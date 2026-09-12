//! Bounded immutable and signed mutable DHT values.
use super::*;
use crypto::{PublicKey, Signature};
use wire::Decoder;

pub const MAX_VALUE: usize = 512;
pub const MAX_SALT: usize = 32;
pub const MAX_VALUES: usize = 1024;
pub const VALUE_TTL_SECS: u64 = 3600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutableValue {
    pub publisher: PublicKey,
    pub salt: Vec<u8>,
    pub sequence: u64,
    pub value: Vec<u8>,
    pub expires: u64,
    pub signature: Signature,
}
impl MutableValue {
    pub fn sign(
        key: &Keypair,
        salt: Vec<u8>,
        sequence: u64,
        value: Vec<u8>,
        expires: u64,
    ) -> Result<Self, Error> {
        if salt.len() > MAX_SALT || value.len() > MAX_VALUE {
            return Err(Error::Invalid);
        }
        let signature = key.sign(&mutable_message(
            key.public(),
            &salt,
            sequence,
            &value,
            expires,
        ));
        Ok(Self {
            publisher: key.public(),
            salt,
            sequence,
            value,
            expires,
            signature,
        })
    }
    pub fn key(&self) -> NodeId {
        let mut e = Encoder::new();
        e.raw(b"warren:dht-next:mutable-key:v1")
            .raw(self.publisher.as_bytes())
            .bytes(&self.salt);
        NodeId::from_bytes(crypto::hash(e.as_slice()))
    }
    pub fn verify(&self, now: Time) -> bool {
        self.salt.len() <= MAX_SALT
            && self.value.len() <= MAX_VALUE
            && self.expires > now.unix_secs
            && self.expires <= now.unix_secs.saturating_add(VALUE_TTL_SECS)
            && self
                .publisher
                .verify_strict(
                    &mutable_message(
                        self.publisher,
                        &self.salt,
                        self.sequence,
                        &self.value,
                        self.expires,
                    ),
                    &self.signature,
                )
                .is_ok()
    }
}
fn mutable_message(
    publisher: PublicKey,
    salt: &[u8],
    sequence: u64,
    value: &[u8],
    expires: u64,
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.raw(b"warren:dht-next:mutable-value:v1")
        .raw(publisher.as_bytes())
        .bytes(salt)
        .u64_le(sequence)
        .u64_le(expires)
        .bytes(value);
    e.into_vec()
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Immutable(Vec<u8>),
    Mutable(Box<MutableValue>),
}
impl From<MutableValue> for Value {
    fn from(value: MutableValue) -> Self {
        Self::Mutable(Box::new(value))
    }
}
impl Value {
    pub fn key(&self) -> NodeId {
        #[cfg(feature = "diagnostics")]
        let _span = crate::diagnostics::span(crate::diagnostics::Region::ValueKey);
        match self {
            Self::Immutable(bytes) => {
                let mut e = Encoder::new();
                e.raw(b"warren:dht-next:immutable-value:v1").bytes(bytes);
                NodeId::from_bytes(crypto::hash(e.as_slice()))
            }
            Self::Mutable(value) => value.key(),
        }
    }
    pub fn verify(&self, now: Time) -> bool {
        match self {
            Self::Immutable(bytes) => bytes.len() <= MAX_VALUE,
            Self::Mutable(value) => value.verify(now),
        }
    }
}
/// Observations from a bounded value traversal, not a global consistency guarantee.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValueLookupResult {
    pub value: Option<Value>,
    pub responses: usize,
    pub attempted: usize,
    pub timed_out: bool,
    pub conflicting: bool,
}
impl ValueLookupResult {
    pub(super) fn observe(&mut self, value: Option<Value>) {
        self.responses += 1;
        let Some(value) = value else {
            return;
        };
        match (&self.value, &value) {
            (Some(Value::Mutable(old)), Value::Mutable(new)) if new.sequence < old.sequence => {}
            (Some(Value::Mutable(old)), Value::Mutable(new)) if new.sequence == old.sequence => {
                self.conflicting |= old != new;
            }
            _ => {
                self.value = Some(value);
                self.conflicting = false;
            }
        }
    }
}

pub(super) struct Stored {
    value: Value,
    expires: u64,
    owner: NodeId,
    source: SocketAddr,
}
impl Dht {
    /// Write one replica. A mutable CAS compares the currently stored sequence;
    /// `None` accepts a newer sequence or an identical idempotent retry.
    pub fn put_value(
        &mut self,
        coordinator: Contact,
        value: Value,
        cas: Option<u64>,
        now: Time,
    ) -> Result<([u8; 32], Vec<Action>), Error> {
        if !value.verify(now) || (cas.is_some() && matches!(value, Value::Immutable(_))) {
            return Err(Error::Invalid);
        }
        let mut actions = Vec::new();
        let request = self.request(
            coordinator,
            Body::PutValue { value, cas },
            None,
            now,
            &mut actions,
        )?;
        Ok((request, actions))
    }
    /// Read one replica. Validate several replicas when choosing a mutable sequence.
    pub fn get_value(
        &mut self,
        coordinator: Contact,
        key: NodeId,
        now: Time,
    ) -> Result<([u8; 32], Vec<Action>), Error> {
        let mut actions = Vec::new();
        let request = self.request(coordinator, Body::GetValue(key), None, now, &mut actions)?;
        Ok((request, actions))
    }
    /// Cancel a standalone value read without treating its peer as unresponsive.
    /// Completed requests and RPCs owned by a lookup are unaffected.
    pub fn cancel_value_read(&mut self, request: [u8; 32]) -> bool {
        if self.pending.get(&request).is_some_and(|pending| {
            pending.query.is_none() && matches!(pending.packet.body, Body::GetValue(_))
        }) {
            self.pending.remove(&request);
            true
        } else {
            false
        }
    }

    /// Stop retries for a standalone value write without penalizing its peer.
    /// This does not undo a remote write or establish whether it was stored.
    pub fn cancel_value_write(&mut self, request: [u8; 32]) -> bool {
        if self.pending.get(&request).is_some_and(|pending| {
            pending.query.is_none() && matches!(pending.packet.body, Body::PutValue { .. })
        }) {
            self.pending.remove(&request);
            true
        } else {
            false
        }
    }

    pub(super) fn stored_value(&self, key: NodeId, now: Time) -> Option<Value> {
        self.values
            .get(&key)
            .filter(|s| {
                s.expires > now.monotonic_ms
                    && match &s.value {
                        Value::Immutable(_) => true,
                        Value::Mutable(value) => value.expires > now.unix_secs,
                    }
            })
            .map(|s| s.value.clone())
    }
    pub(super) fn store_value(
        &mut self,
        sender: Contact,
        value: &Value,
        cas: Option<u64>,
        now: Time,
    ) -> bool {
        if !value.verify(now) {
            return false;
        }
        let key = value.key();
        let existing = self.values.get(&key);
        if cas.is_some_and(|expected| !matches!(existing.map(|s| &s.value), Some(Value::Mutable(old)) if old.sequence == expected)) { return false; }
        if let Some(old) = existing {
            match (&old.value, value) {
                (Value::Immutable(a), Value::Immutable(b)) if a == b && cas.is_none() => {}
                (Value::Mutable(a), Value::Mutable(b)) if b.sequence > a.sequence || a == b => {}
                _ => return false,
            }
        }
        let owner = match value {
            Value::Immutable(_) => sender.id,
            Value::Mutable(v) => node_id(v.publisher),
        };
        if existing.is_none()
            && (self.values.len() >= MAX_VALUES
                || self.values.values().filter(|s| s.owner == owner).count() >= 16
                || self
                    .values
                    .values()
                    .filter(|s| {
                        routing::network_prefix(s.source) == routing::network_prefix(sender.addr)
                    })
                    .count()
                    >= 64)
        {
            return false;
        }
        let ttl = match value {
            Value::Immutable(_) => VALUE_TTL_SECS,
            Value::Mutable(v) => v.expires.saturating_sub(now.unix_secs),
        };
        let mut expires = now.monotonic_ms.saturating_add(ttl.saturating_mul(1000));
        if let Some(old) = existing {
            if matches!(value, Value::Mutable(_)) && old.value == *value {
                expires = expires.min(old.expires);
            }
        }
        let source = existing.map_or(sender.addr, |s| s.source);
        let owner = existing.map_or(owner, |s| s.owner);
        self.values.insert(
            key,
            Stored {
                value: value.clone(),
                expires,
                owner,
                source,
            },
        );
        #[cfg(feature = "test-support")]
        {
            self.test_has_written = true;
            if self.test_storage.discard_writes {
                self.values.remove(&key);
            }
        }
        true
    }
    pub(super) fn expire_values(&mut self, now: Time) {
        self.values.retain(|_, s| {
            s.expires > now.monotonic_ms
                && match &s.value {
                    Value::Immutable(_) => true,
                    Value::Mutable(v) => v.expires > now.unix_secs,
                }
        });
    }
}
pub(super) fn encode(e: &mut Encoder, value: &Value) {
    match value {
        Value::Immutable(bytes) => {
            e.u8(0).bytes(bytes);
        }
        Value::Mutable(v) => {
            e.u8(1)
                .raw(v.publisher.as_bytes())
                .bytes(&v.salt)
                .u64_le(v.sequence)
                .u64_le(v.expires)
                .bytes(&v.value)
                .raw(&v.signature.to_bytes());
        }
    }
}
pub(super) fn decode(d: &mut Decoder<'_>) -> Option<Value> {
    match d.u8().ok()? {
        0 => {
            let bytes = d.bytes().ok()?;
            (bytes.len() <= MAX_VALUE).then(|| Value::Immutable(bytes.to_vec()))
        }
        1 => {
            let publisher = PublicKey::from_bytes(&d.array().ok()?).ok()?;
            let salt = d.bytes().ok()?;
            if salt.len() > MAX_SALT {
                return None;
            }
            let salt = salt.to_vec();
            let sequence = d.u64_le().ok()?;
            let expires = d.u64_le().ok()?;
            let bytes = d.bytes().ok()?;
            if bytes.len() > MAX_VALUE {
                return None;
            }
            let value = bytes.to_vec();
            let signature = Signature::from_bytes(d.array().ok()?);
            Some(Value::from(MutableValue {
                publisher,
                salt,
                sequence,
                expires,
                value,
                signature,
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(n: u8) -> Keypair {
        Keypair::from_seed(&[n; 32])
    }
    fn peer(n: u8) -> Contact {
        Contact::new(
            node_id(key(n).public()),
            format!("192.0.{n}.1:4000").parse().unwrap(),
        )
    }
    fn now() -> Time {
        Time::new(100_000, 100)
    }
    fn core() -> Dht {
        Dht::new(key(1), [111; 32], true)
    }
    #[test]
    fn cancel_value_read_preserves_writes_and_lookup_owned_requests() {
        let mut dht = core();
        let value = Value::Immutable(b"cancel".to_vec());
        let (read, _) = dht.get_value(peer(2), value.key(), now()).unwrap();
        let (write, _) = dht.put_value(peer(3), value.clone(), None, now()).unwrap();
        let (query, _) = dht.lookup_value(value.key(), &[peer(4)], now()).unwrap();
        let lookup_requests: Vec<_> = dht
            .pending
            .iter()
            .filter(|(_, p)| p.query == Some(query))
            .map(|(id, _)| *id)
            .collect();
        assert!(!lookup_requests.is_empty());
        let count = dht.pending_len();
        assert!(!dht.cancel_value_read(write));
        for request in lookup_requests {
            assert!(!dht.cancel_value_read(request));
        }
        assert!(dht.cancel_value_read(read));
        assert!(!dht.cancel_value_read(read));
        assert_eq!(dht.pending_len(), count - 1);
    }

    #[test]
    fn cancel_value_write_preserves_reads_lookups_and_other_writes() {
        let mut dht = core();
        let value = Value::Immutable(b"cancel write".to_vec());
        let (read, _) = dht.get_value(peer(2), value.key(), now()).unwrap();
        let (write, _) = dht.put_value(peer(3), value.clone(), None, now()).unwrap();
        let (other_write, _) = dht.put_value(peer(4), value.clone(), None, now()).unwrap();
        let (query, _) = dht.lookup_value(value.key(), &[peer(5)], now()).unwrap();
        let lookup_requests: Vec<_> = dht
            .pending
            .iter()
            .filter(|(_, p)| p.query == Some(query))
            .map(|(id, _)| *id)
            .collect();
        assert!(!lookup_requests.is_empty());
        let count = dht.pending_len();
        assert!(!dht.cancel_value_write(read));
        for request in lookup_requests {
            assert!(!dht.cancel_value_write(request));
        }
        assert!(dht.cancel_value_write(write));
        assert!(!dht.cancel_value_write(write));
        assert_eq!(dht.pending_len(), count - 1);
        assert!(dht.pending.contains_key(&other_write));
    }

    fn mutable(sequence: u64, bytes: &[u8], expires: u64) -> Value {
        Value::from(
            MutableValue::sign(&key(2), b"feed".to_vec(), sequence, bytes.to_vec(), expires)
                .unwrap(),
        )
    }
    #[test]
    fn mutable_sequences_cas_and_signatures_prevent_overwrites() {
        let mut d = core();
        let first = mutable(1, b"one", 400);
        let next = mutable(2, b"two", 500);
        assert_eq!(first.key(), next.key());
        assert!(!d.store_value(peer(3), &first, Some(0), now()));
        assert!(d.store_value(peer(3), &first, None, now()));
        assert!(!d.store_value(peer(3), &next, Some(0), now()));
        assert!(!d.store_value(peer(3), &mutable(1, b"fork", 400), None, now()));
        assert!(d.store_value(peer(3), &next, Some(1), now()));
        assert!(d.store_value(peer(3), &next, None, now()));
        assert!(!d.store_value(peer(3), &first, None, now()));
        assert_eq!(d.stored_value(first.key(), now()), Some(next));
        let Value::Mutable(mut forged) = first else {
            unreachable!()
        };
        forged.sequence = 3;
        assert!(!d.store_value(peer(2), &Value::Mutable(forged), None, now()));
    }
    #[test]
    fn identical_mutable_republish_cannot_extend_monotonic_expiry_after_wall_clock_rollback() {
        let mut d = core();
        let value = mutable(1, b"one", 400);
        assert!(d.store_value(peer(2), &value, None, now()));
        assert!(d.store_value(peer(3), &value, None, Time::new(200_000, 150)));
        assert_eq!(d.values[&value.key()].expires, 400_000);
        d.expire_values(Time::new(400_000, 350));
        assert!(d
            .stored_value(value.key(), Time::new(400_000, 350))
            .is_none());
    }
    #[test]
    fn immutable_keys_quotas_and_expiry_are_bounded() {
        let mut d = core();
        for n in 0..16 {
            assert!(d.store_value(peer(2), &Value::Immutable(vec![n]), None, now()));
        }
        assert!(!d.store_value(peer(2), &Value::Immutable(vec![16]), None, now()));
        assert!(d.store_value(peer(3), &Value::Immutable(vec![16]), None, now()));
        let value = Value::Immutable(vec![0]);
        assert!(d.store_value(peer(2), &value, None, Time::new(200_000, 200)));
        assert_ne!(value.key(), Value::Immutable(vec![1]).key());
        d.expire_values(Time::new(3_700_001, 1));
        assert_eq!(d.values.len(), 1);
        assert!(d
            .stored_value(value.key(), Time::new(3_700_001, 1))
            .is_some());
        assert!(!d.store_value(peer(2), &value, Some(0), now()));
    }
    #[test]
    fn maximum_values_round_trip_and_limits_reject_oversize() {
        let value = Value::from(
            MutableValue::sign(
                &key(2),
                vec![1; MAX_SALT],
                u64::MAX,
                vec![2; MAX_VALUE],
                400,
            )
            .unwrap(),
        );
        let mut e = Encoder::new();
        encode(&mut e, &value);
        assert_eq!(decode(&mut Decoder::new(e.as_slice())), Some(value.clone()));
        assert!(value.verify(now()));
        assert!(MutableValue::sign(&key(2), vec![0; MAX_SALT + 1], 0, vec![], 400).is_err());
        assert!(MutableValue::sign(&key(2), vec![], 0, vec![0; MAX_VALUE + 1], 400).is_err());
        let mut e = Encoder::new();
        encode(&mut e, &Value::Immutable(vec![0; MAX_VALUE + 1]));
        assert!(decode(&mut Decoder::new(e.as_slice())).is_none());
        assert!(!mutable(0, b"x", 100).verify(now()));
        assert!(!mutable(0, b"x", 100 + VALUE_TTL_SECS + 1).verify(now()));
    }
}
