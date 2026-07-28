//! LAN discovery — the multicast I/O and the local connect broker.
//!
//! Wraps the sans-IO core ([`swarm::lan`]) in real sockets: a [`LanBeacon`] joins a
//! site-local multicast group, advertises this node (where to reach it locally + the blinded
//! topics it's in) every few seconds, and records the same-topic peers it hears. A session
//! reads [`peers`](LanBeacon::peers) to prefer a LAN peer over the DHT — so two devices on
//! the same network find each other with no backbone. See `docs/lan-discovery.md`.
//!
//! ## Why there's a control socket
//!
//! A [`Channel`](crate::Channel) *is* one UDP socket, and the punch primitives consume it:
//! `accept_any` waits for one `PROBE` and hands the socket back as that channel. There's no
//! "listening socket that yields many channels". On the DHT path the coordinator signals each
//! inbound connect so the node can spin up a fresh data socket per signal; on a LAN there is
//! no coordinator — that's the point — so something local has to play that role.
//!
//! Hence one persistent *unconnected* *control* socket that only ever brokers: it receives
//! small signed [`Connect`] requests and, per request, spawns an ordinary punch on a fresh
//! data socket. The control socket never becomes a channel. Its address is what the beacon
//! advertises, so it rides only link-local multicast and is never known off the segment.
//!
//! Roles are deterministic to avoid a double-connect: for a discovered pair the **lower node
//! id requests**, the higher id answers. See `docs/lan-direct-connect.md`.
//!
//! Cross-platform: one `UdpSocket` implementation for every platform. The only per-platform
//! concern is iOS, which needs the multicast entitlement + local-network usage description
//! (handled in the app shell). `SO_REUSEADDR`/`SO_REUSEPORT` (via `socket2`) let several
//! nodes share the group port — needed for two instances on one host (tests) and harmless in
//! the field.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crypto::{Hash, Keypair};
use socket2::{Domain, Protocol, Socket, Type};
use swarm::lan::{Beacon, Connect, Peers};
use swarm::NodeId;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::{connect_channel, Channel, PunchConfig};

/// Site-local multicast group (scope: this network segment — never routed off the LAN).
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 98);
/// Well-known port for the beacon group.
const PORT: u16 = 41799;
/// How often to re-advertise (the first beacon fires immediately on start).
const BEACON_INTERVAL: Duration = Duration::from_secs(3);
/// How long a peer stays a provider after its last beacon before it ages out.
const PEER_TTL_MS: u64 = 15_000;

/// Shared between the [`LanBeacon`] handle and its background tasks.
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

    fn topics(&self) -> Vec<Hash> {
        self.topics.lock().expect("lan topics").clone()
    }
}

/// A running LAN subsystem: the discovery beacon plus the control socket that brokers inbound
/// local connects. Hold it while you want to be discoverable and to see LAN peers; dropping it
/// stops both tasks.
#[must_use = "dropping the LanBeacon stops LAN discovery immediately"]
pub struct LanBeacon {
    shared: Arc<Shared>,
    /// Where peers send us a [`Connect`] — the address the beacon advertises.
    control_addr: SocketAddr,
    /// Kept for the requester side: a [`Connect`] is signed under this key.
    identity: Keypair,
    /// The interface we bind data sockets on, matching what the beacon advertises.
    lan_ip: IpAddr,
    punch: PunchConfig,
    beacon_task: tokio::task::JoinHandle<()>,
    control_task: tokio::task::JoinHandle<()>,
}

impl Drop for LanBeacon {
    fn drop(&mut self) {
        self.beacon_task.abort();
        self.control_task.abort();
    }
}

impl LanBeacon {
    /// Start LAN discovery: bind a control socket on `lan_ip`, join the multicast group, and
    /// beacon the control address plus the current `topics` — the node's blinded per-epoch
    /// channel topics — every `BEACON_INTERVAL`, recording same-topic peers heard. Inbound
    /// [`Connect`] requests are brokered into channels delivered on `incoming`, the same stream
    /// DHT-punched inbound channels arrive on, so nothing downstream can tell them apart.
    ///
    /// Returns an error if either socket can't be set up (a network with no multicast, say), so
    /// the caller can simply skip LAN and fall back to the DHT.
    pub async fn start(
        identity: Keypair,
        lan_ip: IpAddr,
        topics: Vec<Hash>,
        punch: PunchConfig,
        incoming: mpsc::Sender<Channel>,
    ) -> io::Result<LanBeacon> {
        let socket = bind_multicast()?;
        // Port 0: the control address is learned from the beacon, never guessed, so it needs
        // no well-known port — and an ephemeral one avoids colliding with anything.
        let control = UdpSocket::bind(SocketAddr::new(lan_ip, 0)).await?;
        let control_addr = control.local_addr()?;
        let me = NodeId::from_bytes(crypto::hash(identity.public().as_bytes()));
        let shared = Arc::new(Shared {
            peers: Mutex::new(Peers::new()),
            topics: Mutex::new(topics),
            start: Instant::now(),
        });
        let beacon_task = tokio::spawn(run(
            socket,
            identity.clone(),
            control_addr,
            me,
            shared.clone(),
        ));
        let control_task = tokio::spawn(serve_control(
            control,
            lan_ip,
            punch,
            incoming,
            shared.clone(),
        ));
        Ok(LanBeacon {
            shared,
            control_addr,
            identity,
            lan_ip,
            punch,
            beacon_task,
            control_task,
        })
    }

    /// Request a direct LAN connection from the peer whose control socket is `control_addr`
    /// (learned from its beacon). `Ok(None)` means the punch didn't complete — the peer never
    /// answered, or answered too late.
    ///
    /// We are the **Requester**: we bind a fresh data socket, tell the peer where it is, then
    /// *accept* on it, because the Responder is the one that dials back. That asymmetry is
    /// deliberate — advertising only our address means the peer never has to send a port back,
    /// so one unicast message replaces a round trip. On a LAN there is nothing to traverse, so
    /// the punch is a formality that succeeds on the first probe; reusing it keeps one code
    /// path with the DHT case rather than a second, differently-tested one.
    ///
    /// Identity is *not* established here. The `Connect` signature is only a cheap garbage
    /// filter; the caller still runs the usual identity-pinned Noise handshake over the
    /// returned channel, so a forged request costs one failed handshake and nothing more.
    pub async fn dial(&self, control_addr: SocketAddr) -> io::Result<Option<Channel>> {
        let data = UdpSocket::bind(SocketAddr::new(self.lan_ip, 0)).await?;
        let addr = data.local_addr()?;
        let req = Connect::sign(&self.identity, addr, self.shared.topics());
        // Unicast, unacknowledged: if it's lost the accept below simply times out and the
        // caller falls back to the DHT, which is the same outcome as the peer being gone.
        data.send_to(&req.encode(), control_addr).await?;
        let established = puncher::accept_any(data, &[control_addr.ip()], &self.punch).await?;
        connect_channel(established).await
    }

    /// Where peers send us a [`Connect`]. Advertised only on the link-local beacon.
    pub fn control_addr(&self) -> SocketAddr {
        self.control_addr
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

/// Whether `ip` is on a local segment: RFC1918 / CGNAT-shared / link-local for v4, unique-local
/// or link-local for v6. Loopback counts too, so two nodes on one host (the tests, and a
/// desktop running two instances) work without a special case.
///
/// This is the WAN-safety gate. Everything reachable from the internet is refused, so the
/// control socket can't become a cold-connect surface even though it accepts from strangers —
/// the beacon that carries its address never leaves the segment, but an attacker who guessed it
/// still can't use it from off-link.
fn is_lan_scoped(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || v4.is_loopback()
                // 100.64.0.0/10 — carrier NAT, which is what a phone hotspot hands out.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                // fc00::/7 unique-local, fe80::/10 link-local.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The control loop: broker each inbound [`Connect`] into a channel on `incoming`.
///
/// Runs until the [`LanBeacon`] is dropped. Every request is checked before it costs us a
/// socket: a valid signature, a topic we share, a LAN-scoped source, a sender we've actually
/// heard beacon, and a data address on the same host that asked. Anything else is dropped
/// silently — a bad request should cost a decode and nothing else.
async fn serve_control(
    socket: UdpSocket,
    lan_ip: IpAddr,
    punch: PunchConfig,
    incoming: mpsc::Sender<Channel>,
    shared: Arc<Shared>,
) {
    let mut buf = [0u8; 2048];
    loop {
        let Ok((n, src)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        if !is_lan_scoped(src.ip()) {
            continue;
        }
        let Ok(req) = Connect::decode(&buf[..n]) else {
            continue;
        };
        if !req.verify() || !req.shares_topic(&shared.topics()) {
            continue;
        }
        // Only answer someone we've heard beacon. A request from a node we've never seen is
        // either stale or forged, and answering it would let an unknown host spend our sockets.
        let now = shared.now_ms();
        let known = shared
            .peers
            .lock()
            .expect("lan peers")
            .fresh(now, PEER_TTL_MS)
            .into_iter()
            .any(|(id, _)| id == req.node_id());
        if !known {
            continue;
        }
        // Dial only back to the host that asked. Honouring an arbitrary `addr` would make this
        // socket a reflector: anyone could aim our probes at a third party by claiming its
        // address. The port may differ (it's a fresh data socket); the host may not.
        if req.addr.ip() != src.ip() {
            continue;
        }
        let peer_addr = req.addr;
        let incoming = incoming.clone();
        // Per-request task: a punch waits on a deadline, and doing that inline would stall the
        // loop and drop every other request meanwhile.
        tokio::spawn(async move {
            let Ok(data) = UdpSocket::bind(SocketAddr::new(lan_ip, 0)).await else {
                return;
            };
            let Ok(established) = puncher::connect_to(data, peer_addr, &punch).await else {
                return;
            };
            if let Ok(Some(channel)) = connect_channel(established).await {
                // Into the same stream DHT-punched inbound channels use, so the serve loop and
                // the Noise accept treat a LAN channel identically.
                let _ = incoming.send(channel).await;
            }
        });
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
    control_addr: SocketAddr,
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
                // The control address, not a data address: a peer's first move is to send us a
                // `Connect`, and data sockets are per-connection and don't exist yet.
                let beacon = Beacon::sign(&identity, vec![control_addr], topics);
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

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    async fn start(seed: u8, topics: Vec<Hash>) -> (LanBeacon, mpsc::Receiver<Channel>, NodeId) {
        let id = crypto::Keypair::from_seed(&[seed; 32]);
        let node = NodeId::from_bytes(crypto::hash(id.public().as_bytes()));
        let (tx, rx) = mpsc::channel(4);
        let beacon = LanBeacon::start(id, loopback(), topics, PunchConfig::default(), tx)
            .await
            .expect("bind");
        (beacon, rx, node)
    }

    /// Poll `f` until it holds, or fail after `secs`. The beacon interval is seconds long, so
    /// every assertion here is necessarily "eventually".
    async fn until(secs: u64, label: &str, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !f() {
            assert!(Instant::now() < deadline, "{label}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Two beacons on one host, same multicast group + a shared topic, discover each other.
    // Requires multicast loopback on this host; ignored by default so CI without multicast
    // doesn't flake — run explicitly (`cargo test -p driver -- --ignored lan`) on a real box.
    #[tokio::test]
    #[ignore = "requires multicast loopback; verify on a real host/LAN"]
    async fn two_beacons_discover_each_other() {
        let shared_topic = vec![topic(42)];
        let (a, _a_rx, a_node) = start(1, shared_topic.clone()).await;
        let (b, _b_rx, b_node) = start(2, shared_topic).await;

        until(4, "beacons never discovered each other", || {
            a.peers().iter().any(|(id, _)| *id == b_node)
                && b.peers().iter().any(|(id, _)| *id == a_node)
        })
        .await;

        // What's surfaced is the peer's control address — where a `Connect` goes.
        let (_, b_addr) = a.peers().into_iter().find(|(id, _)| *id == b_node).unwrap();
        assert_eq!(b_addr, b.control_addr());
    }

    // The whole local leg with no DHT and no coordinator in the process: A and B beacon, A dials
    // B's control socket, B's broker punches back, and both ends get a live channel that carries
    // bytes. This is the claim the feature rests on, so it asserts data flow, not just a handle.
    #[tokio::test]
    #[ignore = "requires multicast loopback; verify on a real host/LAN"]
    async fn dial_over_the_lan_yields_a_channel_both_ways() {
        let shared_topic = vec![topic(7)];
        let (a, _a_rx, _a_node) = start(3, shared_topic.clone()).await;
        let (b, mut b_rx, b_node) = start(4, shared_topic).await;

        // B must have heard A before it will answer — the broker only serves known peers.
        until(4, "A never saw B / B never saw A", || {
            a.peers().iter().any(|(id, _)| *id == b_node) && !b.peers().is_empty()
        })
        .await;

        let a_side = a
            .dial(b.control_addr())
            .await
            .expect("dial")
            .expect("punched");
        let b_side = tokio::time::timeout(Duration::from_secs(4), b_rx.recv())
            .await
            .expect("B's broker produced no channel")
            .expect("incoming closed");

        a_side.send(b"ping").await.expect("send");
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), b_side.recv(&mut buf))
            .await
            .expect("no bytes arrived over the LAN channel")
            .expect("recv");
        assert_eq!(&buf[..n], b"ping");
    }

    // A peer we've never heard beacon gets no answer: the broker would otherwise spend a socket
    // and a punch deadline on any host that found the control port.
    #[tokio::test]
    #[ignore = "requires multicast loopback; verify on a real host/LAN"]
    async fn an_unknown_peer_is_refused() {
        // Disjoint topics, so neither ever records the other as a provider.
        let (a, _a_rx, _) = start(5, vec![topic(1)]).await;
        let (b, mut b_rx, _) = start(6, vec![topic(2)]).await;

        // The dial itself times out (nobody punches back) and nothing reaches B's incoming.
        assert!(
            a.dial(b.control_addr()).await.expect("dial ran").is_none(),
            "a stranger's dial was answered"
        );
        assert!(
            b_rx.try_recv().is_err(),
            "an unknown peer produced an inbound channel"
        );
    }

    #[test]
    fn only_local_addresses_are_lan_scoped() {
        for ip in [
            "192.168.1.5",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1", // carrier NAT — what a phone hotspot hands out
        ] {
            assert!(is_lan_scoped(ip.parse().unwrap()), "{ip} should be LAN");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.4",
            "172.32.0.1",
            "99.1.1.1",
        ] {
            assert!(
                !is_lan_scoped(ip.parse().unwrap()),
                "{ip} should not be LAN"
            );
        }
        assert!(is_lan_scoped("::1".parse().unwrap()));
        assert!(is_lan_scoped("fe80::1".parse().unwrap()));
        assert!(is_lan_scoped("fd00::1".parse().unwrap()));
        assert!(!is_lan_scoped("2606:4700::1111".parse().unwrap()));
    }
}
