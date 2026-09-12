//! End-to-end Noise NK over coordinator-forwarded, signed signaling envelopes.
use crate::{node_id, Record, Signal};
use snow::HandshakeState;

const PARAMS: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

/// Decrypted application bytes and the unchanged, independently verifiable envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedSignal {
    pub envelope: Signal,
    pub payload: Vec<u8>,
}

pub(crate) fn keypair() -> snow::Keypair {
    snow::Builder::new(PARAMS.parse().expect("Noise parameters"))
        .generate_keypair()
        .expect("signaling key entropy unavailable")
}

pub(crate) struct RetiredKey {
    pub key: snow::Keypair,
    pub expires: u64,
}
impl Drop for RetiredKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.private.zeroize();
    }
}

fn prologue(signal: &Signal) -> Vec<u8> {
    let mut bytes = b"warren:dht-next:encrypted-signal:v1".to_vec();
    bytes.extend_from_slice(node_id(signal.author).as_bytes());
    bytes.extend_from_slice(signal.recipient.as_bytes());
    bytes.extend_from_slice(&signal.session);
    bytes.extend_from_slice(&signal.expires.to_le_bytes());
    bytes
}

pub(crate) fn offer(
    record: &Record,
    signal: &Signal,
    payload: &[u8],
) -> Option<(HandshakeState, Vec<u8>)> {
    let prologue = prologue(signal);
    let mut state = snow::Builder::new(PARAMS.parse().ok()?)
        .prologue(&prologue)
        .ok()?
        .remote_public_key(&record.signaling_key)
        .ok()?
        .build_initiator()
        .ok()?;
    let bytes = write(&mut state, payload)?;
    Some((state, bytes))
}

pub(crate) fn receive_offer(
    private: &[u8],
    signal: &Signal,
) -> Option<(HandshakeState, ReceivedSignal)> {
    let prologue = prologue(signal);
    let mut state = snow::Builder::new(PARAMS.parse().ok()?)
        .prologue(&prologue)
        .ok()?
        .local_private_key(private)
        .ok()?
        .build_responder()
        .ok()?;
    let opened = read(&mut state, signal)?;
    Some((state, opened))
}

pub(crate) fn write(state: &mut HandshakeState, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > crate::protocol::MAX_SIGNAL {
        return None;
    }
    let mut bytes = vec![0; payload.len() + 48];
    let n = state.write_message(payload, &mut bytes).ok()?;
    bytes.truncate(n);
    Some(bytes)
}

pub(crate) fn read(state: &mut HandshakeState, signal: &Signal) -> Option<ReceivedSignal> {
    let mut payload = vec![0; crate::protocol::MAX_SIGNAL];
    let n = state.read_message(&signal.payload, &mut payload).ok()?;
    payload.truncate(n);
    Some(ReceivedSignal {
        envelope: signal.clone(),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{protocol::MAX_SIGNAL, Contact};
    use crypto::Keypair;

    fn fixture() -> (snow::Keypair, Record, Signal) {
        let provider = Keypair::from_seed(&[2; 32]);
        let caller = Keypair::from_seed(&[1; 32]);
        let keys = keypair();
        let target = node_id(provider.public());
        let record = Record::sign(
            &provider,
            target,
            Contact::new(target, "192.0.2.2:4000".parse().unwrap()),
            300,
            keys.public.as_slice().try_into().unwrap(),
        );
        let signal = Signal::sign(&caller, target, [7; 32], 110, false, vec![]);
        (keys, record, signal)
    }

    #[test]
    fn maximum_payloads_round_trip_and_signatures_cover_ciphertext() {
        let (keys, record, mut signal) = fixture();
        let plain = vec![77; MAX_SIGNAL];
        let (mut caller, ciphertext) = offer(&record, &signal, &plain).unwrap();
        signal = Signal::sign(
            &Keypair::from_seed(&[1; 32]),
            signal.recipient,
            signal.session,
            signal.expires,
            false,
            ciphertext,
        );
        assert!(signal.verify(100));
        assert_eq!(signal.payload.len(), MAX_SIGNAL + 48);
        assert!(!signal.payload.windows(plain.len()).any(|w| w == plain));
        let (mut provider, opened) = receive_offer(&keys.private, &signal).unwrap();
        assert_eq!(opened.payload, plain);
        assert_eq!(opened.envelope, signal);
        assert!(opened.envelope.verify(100));
        let answer = Signal::sign(
            &Keypair::from_seed(&[2; 32]),
            node_id(signal.author),
            signal.session,
            signal.expires,
            true,
            write(&mut provider, &plain).unwrap(),
        );
        assert!(answer.verify(100));
        assert_eq!(read(&mut caller, &answer).unwrap().payload, plain);
        assert!(write(&mut provider, &plain).is_none());
    }

    #[test]
    fn coordinator_keys_and_modified_transcripts_cannot_open_an_offer() {
        let (keys, record, mut signal) = fixture();
        let (_, bytes) = offer(&record, &signal, b"private NAT candidates").unwrap();
        signal.payload = bytes;
        assert!(receive_offer(&keypair().private, &signal).is_none());
        for field in 0..5 {
            let mut bad = signal.clone();
            match field {
                0 => bad.session[0] ^= 1,
                1 => bad.expires += 1,
                2 => bad.author = Keypair::from_seed(&[3; 32]).public(),
                3 => bad.recipient = node_id(Keypair::from_seed(&[3; 32]).public()),
                _ => bad.payload[40] ^= 1,
            }
            assert!(receive_offer(&keys.private, &bad).is_none());
        }
        let mut substituted = record;
        substituted.signaling_key = keypair().public.try_into().unwrap();
        assert!(!substituted.verify(100));
    }

    #[test]
    fn answers_are_bound_to_the_callers_ephemeral_exchange() {
        let (keys, record, mut signal) = fixture();
        let (mut caller, bytes) = offer(&record, &signal, b"offer").unwrap();
        let (mut unrelated, _) = offer(&record, &signal, b"offer").unwrap();
        signal.payload = bytes;
        let (mut provider, _) = receive_offer(&keys.private, &signal).unwrap();
        let answer = Signal::sign(
            &Keypair::from_seed(&[2; 32]),
            node_id(signal.author),
            signal.session,
            signal.expires,
            true,
            write(&mut provider, b"answer").unwrap(),
        );
        assert!(read(&mut unrelated, &answer).is_none());
        assert_eq!(read(&mut caller, &answer).unwrap().payload, b"answer");
    }
}
