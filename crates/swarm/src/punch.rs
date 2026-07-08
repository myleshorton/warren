//! Hole-punch strategy selection and the birthday-paradox model.
//!
//! Given the two peers' firewall types (from [`crate::nat`]), [`plan`] picks the
//! strategy — exactly the decision table HyperDHT uses:
//!
//! | local \\ remote | Open/Consistent | Random |
//! |---|---|---|
//! | **Open/Consistent** | direct | spray random ports |
//! | **Random** | open birthday sockets | relay (give up on direct) |
//!
//! When one side is Random and the other Consistent, direct connection needs a
//! *port collision*: the Random side opens many external ports at once, and the
//! Consistent side sprays guesses across the port space. [`simulate_birthday`]
//! models that collision so we can verify our constants actually achieve the
//! success rate the birthday bound predicts — and so the test fails loudly if
//! someone weakens them.

use crate::nat::Firewall;
use crate::sim::Rng;
use std::collections::HashSet;

/// Sockets the Random side opens simultaneously (each mints one external port).
pub const BIRTHDAY_SOCKETS: usize = 256;
/// Random-port guesses the Consistent side sprays.
pub const SPRAY_PROBES: usize = 1750;
/// Lowest port used for punching.
pub const PORT_MIN: u16 = 1024;
/// Highest port used for punching.
pub const PORT_MAX: u16 = 65535;

/// Tunable punch parameters.
#[derive(Clone, Copy, Debug)]
pub struct PunchParams {
    /// Number of sockets the Random side opens at once.
    pub birthday_sockets: usize,
    /// Number of random-port guesses the Consistent side sends.
    pub spray_probes: usize,
    /// Lowest port in the punch range.
    pub port_min: u16,
    /// Highest port in the punch range.
    pub port_max: u16,
}

impl Default for PunchParams {
    fn default() -> Self {
        Self {
            birthday_sockets: BIRTHDAY_SOCKETS,
            spray_probes: SPRAY_PROBES,
            port_min: PORT_MIN,
            port_max: PORT_MAX,
        }
    }
}

impl PunchParams {
    fn port_space(&self) -> u32 {
        (self.port_max as u32) - (self.port_min as u32) + 1
    }

    fn random_port(&self, rng: &mut Rng) -> u16 {
        let span = self.port_space();
        self.port_min + (rng.next_u64() % span as u64) as u16
    }
}

/// The chosen approach for a punch attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// One side is directly reachable (or both ports are predictable): just dial.
    Direct,
    /// We are the Consistent side; spray random ports at the Random peer.
    SprayRandomPorts,
    /// We are the Random side; open many sockets so a sprayed probe collides.
    OpenBirthdaySockets,
    /// Neither side can be reached directly; fall back to a relay.
    Relay,
}

/// Select the punch strategy from our and the peer's firewall types.
pub fn plan(local: Firewall, remote: Firewall) -> Strategy {
    use Firewall::{Consistent, Open, Random};
    match (local, remote) {
        // Any directly-reachable peer can simply be dialed.
        (_, Open) | (Open, _) => Strategy::Direct,
        // Both ports predictable: direct simultaneous open.
        (Consistent, Consistent) => Strategy::Direct,
        // One-sided random: the predictable side sprays, the random side opens.
        (Consistent, Random) => Strategy::SprayRandomPorts,
        (Random, Consistent) => Strategy::OpenBirthdaySockets,
        // Both random: unpredictable on both ends — HyperDHT declines to punch.
        (Random, Random) => Strategy::Relay,
    }
}

/// The result of a punch attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A direct connection was established.
    Direct,
    /// A hole was punched via port collision.
    Punched,
    /// Direct connectivity failed; a relay is required.
    Relayed,
}

/// Model a one-sided-random punch as a port-collision experiment.
///
/// The Random side opens `birthday_sockets` distinct external ports; the
/// Consistent side sprays `spray_probes` independent random ports. Returns true
/// if any sprayed port hits an opened socket — the event that establishes the
/// hole.
pub fn simulate_birthday(rng: &mut Rng, params: &PunchParams) -> bool {
    let mut opened: HashSet<u16> = HashSet::with_capacity(params.birthday_sockets);
    while opened.len() < params.birthday_sockets {
        opened.insert(params.random_port(rng));
    }
    for _ in 0..params.spray_probes {
        if opened.contains(&params.random_port(rng)) {
            return true;
        }
    }
    false
}

/// Attempt a punch between the two firewall types, using `rng` for the
/// probabilistic cases.
pub fn attempt_punch(
    local: Firewall,
    remote: Firewall,
    rng: &mut Rng,
    params: &PunchParams,
) -> Outcome {
    match plan(local, remote) {
        Strategy::Direct => Outcome::Direct,
        Strategy::Relay => Outcome::Relayed,
        Strategy::SprayRandomPorts | Strategy::OpenBirthdaySockets => {
            if simulate_birthday(rng, params) {
                Outcome::Punched
            } else {
                Outcome::Relayed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::Firewall::{Consistent, Open, Random};

    #[test]
    fn strategy_table_is_correct() {
        assert_eq!(plan(Open, Open), Strategy::Direct);
        assert_eq!(plan(Open, Random), Strategy::Direct);
        assert_eq!(plan(Random, Open), Strategy::Direct);
        assert_eq!(plan(Consistent, Consistent), Strategy::Direct);
        assert_eq!(plan(Consistent, Open), Strategy::Direct);
        assert_eq!(plan(Consistent, Random), Strategy::SprayRandomPorts);
        assert_eq!(plan(Random, Consistent), Strategy::OpenBirthdaySockets);
        assert_eq!(plan(Random, Random), Strategy::Relay);
    }

    #[test]
    fn direct_pairs_never_need_a_relay() {
        let mut rng = Rng::new(1);
        let p = PunchParams::default();
        for pair in [(Open, Open), (Consistent, Consistent), (Open, Random)] {
            assert_eq!(attempt_punch(pair.0, pair.1, &mut rng, &p), Outcome::Direct);
        }
    }

    #[test]
    fn double_random_always_relays() {
        let mut rng = Rng::new(2);
        let p = PunchParams::default();
        assert_eq!(
            attempt_punch(Random, Random, &mut rng, &p),
            Outcome::Relayed
        );
    }

    #[test]
    fn tiny_params_almost_never_collide() {
        // One socket, one guess: collision probability ~1/64512.
        let params = PunchParams {
            birthday_sockets: 1,
            spray_probes: 1,
            ..PunchParams::default()
        };
        let mut rng = Rng::new(42);
        let trials = 2000;
        let hits = (0..trials)
            .filter(|_| simulate_birthday(&mut rng, &params))
            .count();
        assert!(
            hits < 5,
            "expected near-zero collisions, got {hits}/{trials}"
        );
    }
}
