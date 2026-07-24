//! LAN discovery — the multicast I/O.
//!
//! Wraps the sans-IO beacon core ([`swarm::lan`]) in a real multicast socket + timer: a
//! [`LanBeacon`] joins a site-local multicast group, advertises this node (its LAN data
//! address + the blinded topics it's in) every few seconds, and records the same-topic peers
//! it hears. A session holds one and reads [`peers`](LanBeacon::peers) to prefer a LAN peer
//! over the DHT — so two devices on the same network find each other with no backbone. See
//! `docs/lan-discovery.md`.
//!
//! Cross-platform: this is one `UdpSocket` implementation for every platform. The only
//! per-platform concern is iOS, which needs the multicast entitlement (handled in the app
//! shell). `SO_REUSEADDR`/`SO_REUSEPORT` (via `socket2`) let several nodes share the group
//! port — needed for two instances on one host (tests) and harmless in the field.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crypto::{Hash, Keypair};
use socket2::{Domain, Protocol, Socket, Type};
use swarm::lan::{Beacon, Peers};
use swarm::NodeId;
use tokio::net::UdpSocket;

/// Site-local multicast group (scope: this network segment — never routed off the LAN).
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 98);
/// Well-known port for the beacon group.
const PORT: u16 = 41799;
/// How often to re-advertise (the first beacon fires immediately on start).
const BEACON_INTERVAL: Duration = Duration::from_secs(3);
/// How long a peer stays a provider after its last beacon before it ages out.
const PEER_TTL_MS: u64 = 15_000;

/// Shared between the [`LanBeacon`] handle and its background task.
struct Shared {
    peers: Mutex<Peers>,
    topics: Mutex<Vec<Hash>>,
    /// Monotonic base for the sans-IO clock the provider set expects (`now_ms`).
    start: Instant,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

/// A running LAN discovery beacon. Hold it while you want to be discoverable + to see LAN
/// peers; dropping it stops the multicast task.
#[must_use = "dropping the LanBeacon stops LAN discovery immediately"]
pub struct LanBeacon {
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LanBeacon {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl LanBeacon {
    /// Start LAN discovery: join the multicast group and beacon `lan_addr` (where a peer dials
    /// this node directly on the LAN) plus the current `topics` — the node's blinded per-epoch
    /// channel topics — every `BEACON_INTERVAL`, recording same-topic peers heard. Returns an
    /// error if the multicast socket can't be set up (no multicast on this network), so the
    /// caller can simply skip LAN and fall back to the DHT.
    pub async fn start(
        identity: Keypair,
        lan_addr: SocketAddr,
        topics: Vec<Hash>,
    ) -> io::Result<LanBeacon> {
        let socket = bind_multicast()?;
        let me = NodeId::from_bytes(crypto::hash(identity.public().as_bytes()));
        let shared = Arc::new(Shared {
            peers: Mutex::new(Peers::new()),
            topics: Mutex::new(topics),
            start: Instant::now(),
        });
        let task = tokio::spawn(run(socket, identity, lan_addr, me, shared.clone()));
        Ok(LanBeacon { shared, task })
    }

    /// Replace the advertised topics (e.g. when the channel's epoch rotates, or on switching
    /// channels). Takes effect on the next beacon.
    pub fn set_topics(&self, topics: Vec<Hash>) {
        *self.shared.topics.lock().expect("lan topics") = topics;
    }

    /// The same-channel peers seen on the LAN within the TTL: `(node_id, lan_addr)`, for the
    /// caller to dial directly.
    pub fn peers(&self) -> Vec<(NodeId, SocketAddr)> {
        let now = self.shared.now_ms();
        self.shared
            .peers
            .lock()
            .expect("lan peers")
            .fresh(now, PEER_TTL_MS)
    }
}

/// Bind a UDP socket to the beacon group port with address/port reuse, join the group, and
/// enable multicast loopback (so instances on one host — and the field — hear each other; our
/// own beacons are filtered by node id in [`Peers::observe`]).
fn bind_multicast() -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT)).into())?;
    sock.set_multicast_loop_v4(true)?;
    sock.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into())
}

/// The beacon loop: advertise on a timer, record peers on receipt. Runs until the
/// [`LanBeacon`] is dropped.
async fn run(
    socket: UdpSocket,
    identity: Keypair,
    lan_addr: SocketAddr,
    me: NodeId,
    shared: Arc<Shared>,
) {
    let group = SocketAddr::from((GROUP, PORT));
    let mut interval = tokio::time::interval(BEACON_INTERVAL);
    let mut buf = [0u8; 2048];
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Age out stale peers every tick regardless of our own topics — otherwise a
                // node with no topics yet (before joining, or mid channel-switch) skips the
                // sweep and holds entries observed earlier until it re-joins.
                let now = shared.now_ms();
                shared.peers.lock().expect("lan peers").expire(now, PEER_TTL_MS);
                let topics = shared.topics.lock().expect("lan topics").clone();
                if topics.is_empty() {
                    continue; // not in any channel yet — nothing to advertise
                }
                let beacon = Beacon::sign(&identity, vec![lan_addr], topics);
                let _ = socket.send_to(&beacon.encode(), group).await;
            }
            recv = socket.recv_from(&mut buf) => {
                let Ok((n, _src)) = recv else { continue };
                let Ok(beacon) = Beacon::decode(&buf[..n]) else { continue };
                let now = shared.now_ms();
                let topics = shared.topics.lock().expect("lan topics").clone();
                shared.peers.lock().expect("lan peers").observe(&beacon, now, me, &topics);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topic(b: u8) -> Hash {
        crypto::hash(&[b])
    }

    // Two beacons on one host, same multicast group + a shared topic, discover each other.
    // Requires multicast loopback on this host; ignored by default so CI without multicast
    // doesn't flake — run explicitly (`cargo test -p driver -- --ignored lan`) on a real box.
    #[tokio::test]
    #[ignore = "requires multicast loopback; verify on a real host/LAN"]
    async fn two_beacons_discover_each_other() {
        let a_id = crypto::Keypair::from_seed(&[1; 32]);
        let b_id = crypto::Keypair::from_seed(&[2; 32]);
        let a_node = NodeId::from_bytes(crypto::hash(a_id.public().as_bytes()));
        let b_node = NodeId::from_bytes(crypto::hash(b_id.public().as_bytes()));
        let shared_topic = vec![topic(42)];

        let a = LanBeacon::start(
            a_id,
            "192.168.1.10:5000".parse().unwrap(),
            shared_topic.clone(),
        )
        .await
        .expect("bind A");
        let b = LanBeacon::start(
            b_id,
            "192.168.1.11:5001".parse().unwrap(),
            shared_topic.clone(),
        )
        .await
        .expect("bind B");

        // The first beacon fires immediately; poll until each sees the other.
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let a_sees_b = a.peers().iter().any(|(id, _)| *id == b_node);
            let b_sees_a = b.peers().iter().any(|(id, _)| *id == a_node);
            if a_sees_b && b_sees_a {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "beacons never discovered each other"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // The addresses surfaced are the advertised LAN data addresses.
        let (_, b_addr) = a.peers().into_iter().find(|(id, _)| *id == b_node).unwrap();
        assert_eq!(b_addr, "192.168.1.11:5001".parse().unwrap());
    }
}
