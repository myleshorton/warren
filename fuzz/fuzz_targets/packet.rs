#![no_main]
use crypto::Keypair;
use dht_next::{protocol::MAX_PACKET, Action, Dht, Time, MAX_PENDING};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let mut core = Dht::new(Keypair::from_seed(&[2; 32]), [102; 32], true);
    let source = "198.51.1.1:4000".parse().unwrap();
    for (index, packet) in bytes.chunks(MAX_PACKET + 1).take(16).enumerate() {
        let now = Time::new(index as u64 * 1000, 100 + index as u64);
        let actions = core.receive(source, packet, now);
        for action in actions.into_iter().chain(core.tick(now)) {
            if let Action::Send { bytes, .. } = action {
                assert!(bytes.len() <= MAX_PACKET);
            }
        }
        assert!(core.pending_len() <= MAX_PENDING);
        assert!(core.routing_len() <= 5120);
        assert!(core.registration_len() <= 256);
    }
});
