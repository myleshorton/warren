//! Empirical verification of the hole-punch strategy.
//!
//! The birthday-paradox punch is probabilistic, so we verify it statistically:
//! over many deterministic trials, the one-sided-random case must succeed at
//! close to the rate the birthday bound predicts. This doubles as a guardrail —
//! if the constants (`BIRTHDAY_SOCKETS`, `SPRAY_PROBES`) are ever weakened, the
//! measured rate drops and this test fails.

use swarm::punch::{attempt_punch, simulate_birthday, PunchParams};
use swarm::sim::Rng;
use swarm::{Firewall, Outcome};

/// Analytic birthday bound: P(at least one of `spray` uniform guesses hits one
/// of `sockets` distinct opened ports) ≈ 1 - (1 - sockets/space)^spray.
fn expected_success(params: &PunchParams) -> f64 {
    let space = (params.port_max as f64) - (params.port_min as f64) + 1.0;
    let miss = 1.0 - (params.birthday_sockets as f64) / space;
    1.0 - miss.powi(params.spray_probes as i32)
}

#[test]
fn birthday_punch_matches_the_bound() {
    let params = PunchParams::default();
    let mut rng = Rng::new(0xB144DA1);
    let trials = 5000;

    let successes = (0..trials)
        .filter(|_| simulate_birthday(&mut rng, &params))
        .count();
    let observed = successes as f64 / trials as f64;
    let expected = expected_success(&params);

    // Expected is ~0.999; require the measured rate to sit right next to it.
    assert!(
        (observed - expected).abs() < 0.01,
        "observed {observed:.4} vs expected {expected:.4} (successes {successes}/{trials})"
    );
    assert!(
        observed > 0.99,
        "one-sided-random punch should nearly always succeed, got {observed:.4}"
    );
}

#[test]
fn one_sided_random_punches_from_either_role() {
    // Both role assignments (we spray / we open sockets) exercise the same
    // collision and should almost always punch rather than relay.
    let params = PunchParams::default();
    let mut rng = Rng::new(7);
    let trials = 1000;

    for (local, remote) in [
        (Firewall::Consistent, Firewall::Random),
        (Firewall::Random, Firewall::Consistent),
    ] {
        let punched = (0..trials)
            .filter(|_| attempt_punch(local, remote, &mut rng, &params) == Outcome::Punched)
            .count();
        assert!(
            punched as f64 / trials as f64 > 0.99,
            "{local:?}/{remote:?} punched only {punched}/{trials}"
        );
    }
}

#[test]
fn weak_params_would_fail_the_guardrail() {
    // Demonstrate the guardrail bites: 8 sockets + 8 sprays collides rarely, so
    // relying on these constants would (correctly) fail the rate assertion.
    let weak = PunchParams {
        birthday_sockets: 8,
        spray_probes: 8,
        ..PunchParams::default()
    };
    let mut rng = Rng::new(99);
    let trials = 5000;
    let successes = (0..trials)
        .filter(|_| simulate_birthday(&mut rng, &weak))
        .count();
    let observed = successes as f64 / trials as f64;
    assert!(
        observed < 0.1,
        "weak params should rarely collide, got {observed:.4}"
    );
}
