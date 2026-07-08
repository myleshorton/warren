//! Packet-level punch verification.
//!
//! Unlike `punching.rs` (which checks the probabilistic model), these drive real
//! packets through two `NatBox`es with mapping + filtering. The key result: the
//! packet-level punch and the abstract birthday model agree — two independent
//! derivations of the same outcome, which is strong evidence both are right.

use swarm::punch::{attempt_punch, packet_punch, PunchParams};
use swarm::sim::Rng;
use swarm::{Firewall, Outcome};

fn rate<F: FnMut() -> Outcome>(trials: usize, mut f: F) -> f64 {
    assert!(trials > 0, "rate() needs at least one trial");
    let ok = (0..trials)
        .filter(|_| !matches!(f(), Outcome::Relayed))
        .count();
    ok as f64 / trials as f64
}

#[test]
fn predictable_pairs_connect_directly() {
    let params = PunchParams::default();
    let mut rng = Rng::new(1);
    for (a, b) in [
        (Firewall::Open, Firewall::Open),
        (Firewall::Open, Firewall::Consistent),
        (Firewall::Consistent, Firewall::Open),
        (Firewall::Consistent, Firewall::Consistent),
        (Firewall::Open, Firewall::Random),
        (Firewall::Random, Firewall::Open),
    ] {
        assert_eq!(
            packet_punch(a, b, &mut rng, &params),
            Outcome::Direct,
            "{a:?}/{b:?} should connect directly at packet level"
        );
    }
}

#[test]
fn double_random_relays_at_packet_level() {
    let params = PunchParams::default();
    let mut rng = Rng::new(2);
    assert_eq!(
        packet_punch(Firewall::Random, Firewall::Random, &mut rng, &params),
        Outcome::Relayed
    );
}

#[test]
fn one_sided_random_punches_at_packet_level() {
    let params = PunchParams::default();
    let mut rng = Rng::new(3);
    // Both role orders drive the same collision through real packets.
    for (a, b) in [
        (Firewall::Consistent, Firewall::Random),
        (Firewall::Random, Firewall::Consistent),
    ] {
        let r = rate(1000, || packet_punch(a, b, &mut rng, &params));
        assert!(r > 0.99, "{a:?}/{b:?} punched only {r:.4} of the time");
    }
}

#[test]
fn packet_level_agrees_with_abstract_model() {
    // The whole point: two independent implementations of the one-sided-random
    // punch — real packets vs. the birthday abstraction — reach the same rate.
    let params = PunchParams::default();
    let trials = 3000;

    let mut rng_pkt = Rng::new(0xF00D);
    let packet_rate = rate(trials, || {
        packet_punch(
            Firewall::Random,
            Firewall::Consistent,
            &mut rng_pkt,
            &params,
        )
    });

    let mut rng_abs = Rng::new(0xBEEF);
    let abstract_rate = rate(trials, || {
        attempt_punch(
            Firewall::Random,
            Firewall::Consistent,
            &mut rng_abs,
            &params,
        )
    });

    assert!(
        (packet_rate - abstract_rate).abs() < 0.01,
        "packet-level {packet_rate:.4} vs abstract {abstract_rate:.4} should match"
    );
}
