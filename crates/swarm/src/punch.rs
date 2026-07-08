//! Hole-punch strategy selection and the birthday-paradox model.
//!
//! Given the two peers' firewall types (from [`crate::nat`]), [`plan`] picks the
//! strategy — exactly the decision table HyperDHT uses. Any pair involving an
//! Open (directly reachable) peer is a plain dial:
//!
//! | local \\ remote | Open | Consistent | Random |
//! |---|---|---|---|
//! | **Open** | direct | direct | direct |
//! | **Consistent** | direct | direct | spray random ports |
//! | **Random** | direct | open birthday sockets | relay (give up on direct) |
//!
//! When one side is Random and the other Consistent, direct connection needs a
//! *port collision*: the Random side opens many external ports at once, and the
//! Consistent side sprays guesses across the port space. [`simulate_birthday`]
//! models that collision so we can verify our constants actually achieve the
//! success rate the birthday bound predicts — and so the test fails loudly if
//! someone weakens them.

use crate::nat::Firewall;
use crate::natbox::NatBox;
use crate::sim::Rng;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// A shared rendezvous both peers can reach, used only so a predictable side
/// learns (and can share) its own external port before the punch — standing in
/// for the DHT relay node that brokers a real punch. The address is fictional,
/// like every host in this model (all under 10.0.0.0/8); routability is not
/// modeled.
const RENDEZVOUS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 9999);

fn host(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
}

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

/// Connect to a publicly-reachable `server` by dialing it: the dialer sends
/// first, the server admits it (Open accepts any source) and replies to the
/// observed source, which the dialer's own filter admits because it sent there.
/// Works for any dialer NAT type — this is why any pair involving an Open peer
/// connects directly.
fn dial_reachable(dialer: &mut NatBox, server: &mut NatBox) -> bool {
    let ss = server.open_socket();
    let server_ext = server.send(ss, RENDEZVOUS);
    let sd = dialer.open_socket();
    let dialer_ext = dialer.send(sd, server_ext);
    if server.recv(server_ext.port(), dialer_ext).is_none() {
        return false;
    }
    server.send(ss, dialer_ext);
    dialer.recv(dialer_ext.port(), server_ext).is_some()
}

/// Establish a direct connection between two predictable-port peers via
/// simultaneous open: each learns the other's stable external address, then both
/// send, opening each address-restricted filter. Returns whether traffic flows
/// both ways.
fn direct_open(a: &mut NatBox, b: &mut NatBox) -> bool {
    let sa = a.open_socket();
    let sb = b.open_socket();
    let a_ext = a.send(sa, RENDEZVOUS);
    let b_ext = b.send(sb, RENDEZVOUS);
    // Two rounds so both filters open regardless of arrival order.
    for _ in 0..2 {
        a.send(sa, b_ext);
        b.send(sb, a_ext);
    }
    let a_to_b = b.recv(b_ext.port(), a_ext).is_some();
    let b_to_a = a.recv(a_ext.port(), b_ext).is_some();
    a_to_b && b_to_a
}

/// Run a one-sided-random punch with real packets: the random peer opens many
/// sockets toward the consistent peer's known port (minting one external port
/// each), and the consistent peer sprays random guesses. Success is a guess
/// that lands on an opened port — at which point both filters already admit the
/// other, so the channel is bidirectional.
fn one_sided_random(
    random: &mut NatBox,
    consistent: &mut NatBox,
    rng: &mut Rng,
    params: &PunchParams,
) -> bool {
    let cs = consistent.open_socket();
    let c_ext = consistent.send(cs, RENDEZVOUS);

    // Open one socket per birthday probe toward the consistent peer's known
    // port; each mints a fresh external port in the random NAT. The NatBox
    // records these mappings, so a hit is detected via `random.recv` below.
    for _ in 0..params.birthday_sockets {
        let s = random.open_socket();
        random.send(s, c_ext);
    }

    let r_host = random.host();
    for _ in 0..params.spray_probes {
        let guess = params.random_port(rng);
        let guess_addr = SocketAddr::new(r_host, guess);
        // Spraying opens the consistent side's filter toward this address.
        consistent.send(cs, guess_addr);
        // If the guess hit an opened socket, the random side admits it (it
        // already sent to the consistent side)...
        if random.recv(guess, c_ext).is_some() {
            // ...and the reply is admitted by the consistent side, since the
            // winning spray just opened its filter toward this exact address.
            let r_ext = SocketAddr::new(r_host, guess);
            if consistent.recv(c_ext.port(), r_ext).is_some() {
                return true;
            }
        }
    }
    false
}

/// Attempt a punch with a full packet-level NAT model (mapping + filtering),
/// rather than the probabilistic abstraction of [`attempt_punch`]. The outcome
/// emerges from packets traversing two [`NatBox`]es.
pub fn packet_punch(
    local: Firewall,
    remote: Firewall,
    rng: &mut Rng,
    params: &PunchParams,
) -> Outcome {
    match plan(local, remote) {
        Strategy::Relay => Outcome::Relayed,
        Strategy::Direct => {
            let mut a = NatBox::with_range(local, host(1), params.port_min, params.port_max);
            let mut b = NatBox::with_range(remote, host(2), params.port_min, params.port_max);
            // "Direct" has two mechanisms: dial a reachable (Open) peer, or a
            // simultaneous open between two predictable-port peers.
            let ok = if remote == Firewall::Open {
                dial_reachable(&mut a, &mut b)
            } else if local == Firewall::Open {
                dial_reachable(&mut b, &mut a)
            } else {
                direct_open(&mut a, &mut b)
            };
            if ok {
                Outcome::Direct
            } else {
                Outcome::Relayed
            }
        }
        Strategy::SprayRandomPorts => {
            // We are the consistent side (spraying); the peer is random.
            let mut consistent =
                NatBox::with_range(local, host(1), params.port_min, params.port_max);
            let mut random = NatBox::with_range(remote, host(2), params.port_min, params.port_max);
            if one_sided_random(&mut random, &mut consistent, rng, params) {
                Outcome::Punched
            } else {
                Outcome::Relayed
            }
        }
        Strategy::OpenBirthdaySockets => {
            // We are the random side (opening sockets); the peer is consistent.
            let mut random = NatBox::with_range(local, host(1), params.port_min, params.port_max);
            let mut consistent =
                NatBox::with_range(remote, host(2), params.port_min, params.port_max);
            if one_sided_random(&mut random, &mut consistent, rng, params) {
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
