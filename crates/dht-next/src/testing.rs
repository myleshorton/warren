//! Opt-in fault injection and fuzz harnesses. Absent from default builds.
use crate::{Dht, Value};

#[derive(Clone)]
pub enum ReadFault {
    Missing,
    Silent,
    Value(Value),
}
#[derive(Clone, Default)]
pub struct StorageFaults {
    pub discard_writes: bool,
    /// Activated after an accepted write; initial preflight reads behave normally.
    pub read_after_write: Option<ReadFault>,
}
impl Dht {
    pub fn set_storage_faults_for_testing(&mut self, faults: StorageFaults) {
        self.test_storage = faults;
    }
}

/// Exercise signed, cookie-authorized request parsing and replay with fuzzed bodies.
/// Deterministic identities and secrets are confined to this opt-in test harness.
pub fn fuzz_signed_body(body: &[u8]) {
    use crate::{
        protocol::{Body, Packet, MAX_PACKET},
        Action, Time, MAX_PENDING,
    };
    use crypto::Keypair;
    if body.len() > MAX_PACKET {
        return;
    }
    let signer = Keypair::from_seed(&[1; 32]);
    let mut core = Dht::new(Keypair::from_seed(&[2; 32]), [102; 32], true);
    let source = "198.51.1.1:4000".parse().unwrap();
    let now = Time::new(100_000, 100);
    let mut packet = Packet {
        key: signer.public(),
        destination: core.id(),
        server: true,
        nonce: [42; 32],
        epoch: 0,
        cookie: [0; 32],
        body: Body::Probe,
        exchange: vec![],
    };
    let challenge = core.receive(source, &packet.encode(&signer), now);
    let Action::Send { bytes, .. } = &challenge[0] else {
        panic!("challenge")
    };
    let challenge = Packet::decode(bytes).unwrap();
    assert!(matches!(challenge.body, Body::Challenge));
    packet.cookie = challenge.cookie;
    packet.epoch = challenge.epoch;
    let encoded = packet.encode(&signer);
    // Remove the one-byte Probe body and its signature, retaining a valid grant.
    let mut bytes = encoded[..encoded.len() - 65].to_vec();
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&signer.sign(&bytes).to_bytes());
    if let Some(decoded) = Packet::decode(&bytes) {
        assert_eq!(decoded.encode(&signer), bytes);
    }
    for step in 0..3 {
        let now = Time::new(100_000 + step * 1000, 100 + step);
        let actions = core.receive(source, &bytes, now);
        for action in actions.into_iter().chain(core.tick(now)) {
            if let Action::Send { bytes, .. } = action {
                assert!(bytes.len() <= MAX_PACKET);
            }
        }
        assert!(core.pending_len() <= MAX_PENDING);
        assert!(core.registration_len() <= 256);
    }
}

mod lifecycle;
pub use lifecycle::fuzz_lifecycle;
