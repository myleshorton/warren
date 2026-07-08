//! Real-UDP hole punching: the socket-level mechanics that establish a direct
//! path between two peers, over `tokio` sockets.
//!
//! Which primitive a peer runs is chosen by [`swarm::punch::plan`] from the two
//! peers' firewall types (that decision, and its success probability, are
//! verified in the `swarm` crate). This crate is the *execution*:
//!
//! - [`connect_to`] / [`accept`] — simultaneous open or dial between predictable
//!   endpoints.
//! - [`open_birthday_sockets`] / [`spray`] — the one-sided-random birthday
//!   punch: the random peer opens many sockets and listens (its ports are
//!   unpredictable, as a symmetric NAT's would be); the predictable peer sprays
//!   the port space until a probe collides.
//!
//! Establishment uses a tiny probe handshake: a [`PROBE`] byte, answered by an
//! [`ACK`]. Receiving either from the peer means that socket has a working path.
//!
//! Not yet here (needs a router, so it can't run in CI): UPnP/NAT-PMP/PCP port
//! mapping. Reflexive-address discovery lives with the DHT's NAT sampling.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use swarm::sim::Rng;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::{timeout, Instant};

/// A hole-punch probe.
pub const PROBE: u8 = 1;
/// Acknowledges a [`PROBE`]; its receipt confirms the reverse path.
pub const ACK: u8 = 2;

/// Whether a received datagram is a punch control message: exactly one byte,
/// `PROBE` or `ACK`. Requiring the single-byte length means a multi-byte
/// application payload that merely starts with 1 or 2 can't be mistaken for a
/// punch.
fn is_control_msg(datagram: &[u8]) -> bool {
    matches!(datagram, [PROBE] | [ACK])
}

/// A punched path: a socket with a working route to `peer`.
#[derive(Debug)]
pub struct Established {
    /// The socket that reached the peer.
    pub socket: UdpSocket,
    /// The peer address on the other end of the punched path.
    pub peer: SocketAddr,
}

/// Timing knobs for a punch attempt.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Give up after this long.
    pub overall: Duration,
    /// Gap between successive probes (and how long to wait for a reply each).
    pub probe_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            overall: Duration::from_secs(5),
            probe_interval: Duration::from_millis(50),
        }
    }
}

impl Config {
    /// Tight intervals for spraying/tests.
    pub fn fast() -> Self {
        Self {
            overall: Duration::from_secs(5),
            probe_interval: Duration::from_millis(2),
        }
    }
}

/// Dial or simultaneously open toward a known `peer`: probe until the peer
/// answers (or we time out). Both predictable-port peers run this against each
/// other; a peer dialing a reachable one runs this while the reachable peer runs
/// [`accept`].
pub async fn connect_to(
    socket: UdpSocket,
    peer: SocketAddr,
    cfg: &Config,
) -> io::Result<Option<Established>> {
    let deadline = Instant::now() + cfg.overall;
    let mut buf = [0u8; 64];
    while Instant::now() < deadline {
        socket.send_to(&[PROBE], peer).await?;
        match timeout(cfg.probe_interval, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) if from == peer && is_control_msg(&buf[..n]) => {
                if buf[0] == PROBE {
                    socket.send_to(&[ACK], from).await?;
                }
                return Ok(Some(Established { socket, peer }));
            }
            _ => {} // timeout, stray traffic, or spurious source: keep probing
        }
    }
    Ok(None)
}

/// Wait for a peer to reach us on `socket`, ACK it, and return the path. The
/// reachable side of a dial.
pub async fn accept(socket: UdpSocket, cfg: &Config) -> io::Result<Option<Established>> {
    let deadline = Instant::now() + cfg.overall;
    let mut buf = [0u8; 64];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        match timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) if is_control_msg(&buf[..n]) => {
                // A PROBE needs an ACK back; an ACK already confirms the path.
                if buf[0] == PROBE {
                    socket.send_to(&[ACK], from).await?;
                }
                return Ok(Some(Established { socket, peer: from }));
            }
            Ok(Ok(_)) => {} // stray datagram: keep listening
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(None), // timed out
        }
    }
}

/// The random side of a one-sided-random punch: bind `count` sockets to
/// unpredictable ports in `range` on `host` and listen. Because we never send
/// first, our ports are unobservable to the peer — the peer must find one by
/// spraying. Returns the socket that first receives a probe.
pub async fn open_birthday_sockets(
    host: IpAddr,
    range: (u16, u16),
    count: usize,
    seed: u64,
    cfg: &Config,
) -> io::Result<Option<Established>> {
    assert!(
        range.0 >= 1 && range.0 < range.1,
        "invalid port range {range:?}: need 1 <= start < end"
    );
    let mut rng = Rng::new(seed);
    let span = (range.1 - range.0) as u64;
    let mut set = JoinSet::new();
    let mut opened = 0;
    let mut attempts = 0;
    while opened < count && attempts < count * 20 {
        attempts += 1;
        let port = range.0 + (rng.next_u64() % span) as u16;
        if let Ok(socket) = UdpSocket::bind((host, port)).await {
            opened += 1;
            set.spawn(async move {
                let mut buf = [0u8; 64];
                match socket.recv_from(&mut buf).await {
                    Ok((n, from)) if matches!(&buf[..n], [PROBE]) => Some((socket, from)),
                    _ => None,
                }
            });
        }
    }

    let found = timeout(cfg.overall, async {
        while let Some(joined) = set.join_next().await {
            if let Ok(Some(hit)) = joined {
                return Some(hit);
            }
        }
        None
    })
    .await;

    set.abort_all();
    match found {
        Ok(Some((socket, from))) => {
            socket.send_to(&[ACK], from).await?;
            Ok(Some(Established { socket, peer: from }))
        }
        _ => Ok(None),
    }
}

/// The predictable side of a one-sided-random punch: spray probes at random
/// ports in `range` on `peer_host` until one lands on an opened socket and is
/// answered. Never sprays our own port (avoids a self-hit on loopback).
pub async fn spray(
    bind: SocketAddr,
    peer_host: IpAddr,
    range: (u16, u16),
    probes: usize,
    seed: u64,
    cfg: &Config,
) -> io::Result<Option<Established>> {
    assert!(
        range.0 >= 1 && range.0 < range.1,
        "invalid port range {range:?}: need 1 <= start < end"
    );
    let socket = UdpSocket::bind(bind).await?;
    let own_port = socket.local_addr()?.port();
    let deadline = Instant::now() + cfg.overall;
    let mut rng = Rng::new(seed);
    let span = (range.1 - range.0) as u64;
    let mut buf = [0u8; 64];

    for _ in 0..probes {
        if Instant::now() >= deadline {
            break; // respect the overall deadline even if probes remain
        }
        let port = range.0 + (rng.next_u64() % span) as u16;
        if port == own_port {
            continue; // never spray our own socket (would self-hit)
        }
        socket.send_to(&[PROBE], (peer_host, port)).await?;
        if let Ok(Ok((n, from))) = timeout(cfg.probe_interval, socket.recv_from(&mut buf)).await {
            if is_control_msg(&buf[..n]) {
                // Normally the reply is an ACK; if it's a PROBE, answer it so the
                // peer establishes too.
                if buf[0] == PROBE {
                    socket.send_to(&[ACK], from).await?;
                }
                return Ok(Some(Established { socket, peer: from }));
            }
        }
    }
    Ok(None)
}
