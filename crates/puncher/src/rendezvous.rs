//! Direct candidate nomination: the dialer chooses one path for both endpoints.
use crate::{Config, Established};
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

const MAGIC: &[u8; 4] = b"WPN1";
const SIZE: usize = 37;
const PROBE: u8 = 0;
const ACK: u8 = 1;
const SELECT: u8 = 2;
const CONFIRM: u8 = 3;
fn packet(session: [u8; 32], kind: u8) -> [u8; SIZE] {
    let mut bytes = [0; SIZE];
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4..36].copy_from_slice(&session);
    bytes[36] = kind;
    bytes
}
fn kind(bytes: &[u8], session: [u8; 32]) -> Option<u8> {
    (bytes.len() == SIZE && &bytes[..4] == MAGIC && bytes[4..36] == session).then(|| bytes[36])
}
/// Reply to a late probe/nomination after the socket has entered its handshake.
/// These control packets prove no identity; callers must authenticate the path.
pub fn rendezvous_reply(bytes: &[u8], session: [u8; 32], initiator: bool) -> Option<[u8; SIZE]> {
    match kind(bytes, session)? {
        PROBE => Some(packet(session, ACK)),
        SELECT if !initiator => Some(packet(session, CONFIRM)),
        _ => None,
    }
}
// Shared by the UDP adapter and the deterministic packet-network tests.
struct Nomination {
    peers: Vec<SocketAddr>,
    session: [u8; 32],
    initiator: bool,
    selected: Option<SocketAddr>,
    established: Option<SocketAddr>,
}
impl Nomination {
    fn new(peers: &[SocketAddr], session: [u8; 32], initiator: bool) -> Self {
        Self {
            peers: peers.to_vec(),
            session,
            initiator,
            selected: None,
            established: None,
        }
    }
    fn probes(&self) -> Vec<(SocketAddr, [u8; SIZE])> {
        if let Some(peer) = self.selected {
            vec![(peer, packet(self.session, SELECT))]
        } else {
            self.peers
                .iter()
                .map(|peer| (*peer, packet(self.session, PROBE)))
                .collect()
        }
    }
    fn receive(&mut self, from: SocketAddr, bytes: &[u8]) -> Option<[u8; SIZE]> {
        // An endpoint-dependent NAT may use a different source port toward us
        // than toward the DHT reflector. Constrain discovery to advertised IPs;
        // the session binds controls and Noise subsequently pins the identity.
        if from.port() == 0
            || !self.peers.iter().any(|peer| peer.ip() == from.ip())
            || self.selected.is_some_and(|peer| peer != from)
        {
            return None;
        }
        match kind(bytes, self.session) {
            Some(PROBE | ACK) if self.initiator => {
                self.selected = Some(from);
                Some(packet(self.session, SELECT))
            }
            Some(PROBE) => Some(packet(self.session, ACK)),
            Some(SELECT) if !self.initiator => {
                // Pin the responder too: late controls cannot move the path.
                self.selected = Some(from);
                self.established = Some(from);
                Some(packet(self.session, CONFIRM))
            }
            Some(CONFIRM) if self.initiator && self.selected == Some(from) => {
                self.established = Some(from);
                None
            }
            _ => None,
        }
    }
}
/// Both endpoints open their candidate mappings; only the dialer nominates a
/// path. This prevents crossed IPv4/IPv6 or LAN/public candidate selections.
/// The returned responder must keep answering SELECT via `rendezvous_reply`
/// until the subsequent authenticated handshake has completed.
pub async fn rendezvous(
    socket: UdpSocket,
    peers: &[SocketAddr],
    config: &Config,
    session: [u8; 32],
    initiator: bool,
) -> io::Result<Option<Established>> {
    if peers.is_empty() || peers.len() > 4 || config.probe_interval.is_zero() {
        return Ok(None);
    }
    let deadline = Instant::now() + config.overall;
    let mut nomination = Nomination::new(peers, session, initiator);
    let mut bytes = [0; 1500];
    while Instant::now() < deadline {
        let sent = Instant::now();
        let mut sent_any = false;
        for (peer, bytes) in nomination.probes() {
            sent_any |= socket.send_to(&bytes, peer).await.is_ok();
        }
        if !sent_any {
            return Ok(None);
        }
        loop {
            let remaining = (sent + config.probe_interval)
                .min(deadline)
                .saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (len, from) = match timeout(remaining, socket.recv_from(&mut bytes)).await {
                Ok(result) => result?,
                Err(_) => break,
            };
            if let Some(reply) = nomination.receive(from, &bytes[..len]) {
                socket.send_to(&reply, from).await?;
            }
            if let Some(peer) = nomination.established {
                return Ok(Some(Established { socket, peer }));
            }
        }
    }
    Ok(None)
}

/// Bounded fallback for one-sided endpoint-dependent mappings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatStrategy {
    Direct,
    /// Create outbound mappings from up to 64 sockets.
    OpenMappings,
    /// Probe at most 8192 ports on the advertised peer IPs.
    SearchPorts,
}

/// Select a complementary fallback only when exactly one side has observed
/// different ports on the same public IP. Absence of variation is not proof of
/// endpoint-independent mapping; this remains a bounded best-effort attempt.
pub fn nat_strategy(local_varies: bool, peer_varies: bool) -> NatStrategy {
    match (local_varies, peer_varies) {
        (true, false) => NatStrategy::OpenMappings,
        (false, true) => NatStrategy::SearchPorts,
        _ => NatStrategy::Direct,
    }
}

struct PortSearch {
    rng: crate::Rng,
    sent: usize,
}
impl PortSearch {
    fn new(session: [u8; 32]) -> Self {
        Self {
            rng: crate::Rng::new(u64::from_le_bytes(session[..8].try_into().unwrap())),
            sent: 0,
        }
    }
    fn batch(&mut self, peers: &[SocketAddr]) -> Vec<SocketAddr> {
        let hosts: std::collections::BTreeSet<_> = peers.iter().map(|peer| peer.ip()).collect();
        let mut targets = Vec::new();
        for _ in 0..32 {
            let port = 1024 + (self.rng.next_u64() % (65536 - 1024)) as u16;
            for host in &hosts {
                if self.sent == 8192 {
                    return targets;
                }
                self.sent += 1;
                targets.push(SocketAddr::new(*host, port));
            }
        }
        targets
    }
}

/// Session-bound birthday punching. Extra sockets actively send to create NAT
/// mappings. The dialer nominates one socket/path globally, and all losers close.
pub async fn rendezvous_with_strategy(
    socket: UdpSocket,
    peers: &[SocketAddr],
    config: &Config,
    session: [u8; 32],
    initiator: bool,
    strategy: NatStrategy,
) -> io::Result<Option<Established>> {
    if strategy == NatStrategy::Direct {
        return rendezvous(socket, peers, config, session, initiator).await;
    }
    if peers.is_empty() || peers.len() > 4 || config.probe_interval.is_zero() {
        return Ok(None);
    }
    let deadline = Instant::now() + config.overall;
    let bind = SocketAddr::new(socket.local_addr()?.ip(), 0);
    let mut sockets = vec![std::sync::Arc::new(socket)];
    if strategy == NatStrategy::OpenMappings {
        for _ in 1..64 {
            if Instant::now() >= deadline {
                break;
            }
            if let Ok(socket) = crate::bind_udp(bind) {
                sockets.push(std::sync::Arc::new(socket));
            }
        }
    }
    let mut readers = tokio::task::JoinSet::new();
    let (send, mut incoming) = tokio::sync::mpsc::channel(256);
    for (index, socket) in sockets.iter().enumerate() {
        let socket = socket.clone();
        let send = send.clone();
        readers.spawn(async move {
            let mut bytes = [0; SIZE + 1];
            while let Ok((len, from)) = socket.recv_from(&mut bytes).await {
                if len != SIZE {
                    continue;
                }
                if send.send((index, from, bytes)).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(send);
    let mut nomination = Nomination::new(peers, session, initiator);
    let mut selected_socket = None;
    let mut search = PortSearch::new(session);
    let interval = config.probe_interval.max(std::time::Duration::from_millis(
        if strategy == NatStrategy::OpenMappings {
            250
        } else {
            50
        },
    ));
    let result: io::Result<Option<(usize, SocketAddr)>> = async {
        while Instant::now() < deadline {
            let wake = (Instant::now() + interval).min(deadline);
            if let Some(index) = selected_socket {
                for (to, bytes) in nomination.probes() {
                    let socket: &std::sync::Arc<UdpSocket> = &sockets[index];
                    socket.send_to(&bytes, to).await?;
                }
            } else {
                for socket in &sockets {
                    for (to, bytes) in nomination.probes() {
                        let _ = socket.send_to(&bytes, to).await;
                    }
                }
                if strategy == NatStrategy::SearchPorts {
                    for target in search.batch(peers) {
                        let _ = sockets[0].send_to(&packet(session, PROBE), target).await;
                    }
                }
            }
            loop {
                let (index, from, bytes) =
                    match tokio::time::timeout_at(wake, incoming.recv()).await {
                        Ok(Some(packet)) => packet,
                        Ok(None) => return Ok(None),
                        Err(_) => break,
                    };
                if selected_socket.is_some_and(|selected| selected != index) {
                    continue;
                }
                if let Some(reply) = nomination.receive(from, &bytes[..SIZE]) {
                    sockets[index].send_to(&reply, from).await?;
                }
                if nomination.selected.is_some() {
                    selected_socket = Some(index);
                }
                if let Some(peer) = nomination.established {
                    return Ok(Some((index, peer)));
                }
            }
        }
        Ok(None)
    }
    .await;
    readers.abort_all();
    while readers.join_next().await.is_some() {}
    result.map(|found| {
        found.map(|(index, peer)| Established {
            socket: std::sync::Arc::try_unwrap(sockets.swap_remove(index))
                .expect("readers released socket"),
            peer,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replies_bind_session_role_and_exact_control_encoding() {
        let session = [1; 32];
        assert_eq!(
            rendezvous_reply(&packet(session, PROBE), session, true),
            Some(packet(session, ACK))
        );
        assert_eq!(
            rendezvous_reply(&packet(session, SELECT), session, false),
            Some(packet(session, CONFIRM))
        );
        assert_eq!(
            rendezvous_reply(&packet(session, SELECT), session, true),
            None
        );
        assert_eq!(
            rendezvous_reply(&packet([2; 32], SELECT), session, false),
            None
        );
        assert_eq!(
            rendezvous_reply(&packet(session, CONFIRM), session, false),
            None
        );
        let bytes = packet(session, SELECT);
        for len in 0..bytes.len() {
            assert_eq!(rendezvous_reply(&bytes[..len], session, false), None);
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert_eq!(rendezvous_reply(&extra, session, false), None);
    }
    #[tokio::test]
    async fn confirmation_without_a_nomination_cannot_establish() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let sending = tokio::spawn(async move {
            let mut bytes = [0; 64];
            loop {
                let (_, from) = peer.recv_from(&mut bytes).await.unwrap();
                peer.send_to(&packet([1; 32], CONFIRM), from).await.unwrap();
            }
        });
        let config = Config {
            overall: std::time::Duration::from_millis(80),
            probe_interval: std::time::Duration::from_millis(10),
        };
        assert!(rendezvous(client, &[address], &config, [1; 32], true)
            .await
            .unwrap()
            .is_none());
        sending.abort();
        let _ = sending.await;
    }
}

#[cfg(test)]
#[path = "rendezvous_network.rs"]
mod network;
