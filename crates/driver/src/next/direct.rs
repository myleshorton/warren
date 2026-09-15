//! Candidate gathering on the exact socket later used for the data connection.
use super::{mapping::MappingLease, time, AddressFilter, OverlayId};
use crate::diagnostics::{io_code, Observer, Value};
use crate::{connect_channel, Channel, PunchConfig};
use crypto::Keypair;
use dht_next::{Action, Contact, Dht, Event};
use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// An unconnected data socket and its bounded, observed/local candidate set.
/// Reflection uses authenticated DHT RPCs. It does not establish NAT reachability.
pub struct DirectSocket {
    observer: Observer,
    parent: Option<u64>,
    socket: UdpSocket,
    candidates: Vec<SocketAddr>,
    translation: super::nat64::Translation,
    mapping: Option<MappingLease>,
    address_filter: AddressFilter,
}
impl DirectSocket {
    /// Bind once, ask up to three DHT reflectors, then keep that same mapping for
    /// signaling and punching. No external STUN or signaling service is used.
    pub async fn bind(bind: SocketAddr, reflectors: &[Contact]) -> io::Result<Self> {
        Self::bind_with_mapping(bind, reflectors, None).await
    }
    pub async fn bind_with_mapping(
        bind: SocketAddr,
        reflectors: &[Contact],
        gateway: Option<&portmap::Gateway>,
    ) -> io::Result<Self> {
        let translation = super::nat64::Translation::discover(bind).await;
        Self::bind_with_translation(
            bind,
            reflectors,
            gateway,
            translation,
            Observer::default(),
            None,
            (OverlayId::Global, std::sync::Arc::new(|_| true)),
        )
        .await
    }
    pub(super) async fn bind_with_translation(
        bind: SocketAddr,
        reflectors: &[Contact],
        gateway: Option<&portmap::Gateway>,
        translation: super::nat64::Translation,
        observer: Observer,
        parent: Option<u64>,
        transport: (OverlayId, AddressFilter),
    ) -> io::Result<Self> {
        let (overlay, address_filter) = transport;
        let mut observation = observer.child("nat.reflection", parent);
        observation.field("reflectors", Value::Count(reflectors.len().min(3) as u64));
        observation.field("translation", Value::Text(translation.mode()));
        let result = async {
            let socket = super::bind_socket(bind)?;
            let local = canonical(socket.local_addr()?);
            let dual_stack = bind.is_ipv6();
            let mut candidates = Vec::new();
            let mut core = Dht::new(Keypair::generate(), Keypair::generate().seed(), false);
            let start = Instant::now();
            let mut pending = BTreeSet::new();
            let mut actions = Vec::new();
            for peer in reflectors
                .iter()
                .filter(|peer| address_filter(translation.source(peer.addr)))
                .take(3)
            {
                if let Ok((request, sent)) = core.reflect(*peer, time(start)) {
                    pending.insert(request);
                    actions.extend(sent);
                }
            }
            let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
            let mut bytes = [0; dht_next::protocol::MAX_PACKET + super::overlay::HEADER_LEN + 1];
            loop {
                for action in actions.drain(..) {
                    match action {
                        Action::Send { to, bytes } => {
                            if address_filter(translation.source(to)) {
                                let bytes = overlay.frame(bytes);
                                let _ = socket.send_to(&bytes, translation.destination(to)).await;
                            }
                        }
                        Action::Event(event) => match *event {
                            Event::ObservedAddress {
                                request, address, ..
                            } if pending.remove(&request) => {
                                let address = translation.source(address);
                                if usable(address)
                                    && address_filter(address)
                                    && (dual_stack || address.is_ipv4())
                                    && !candidates.contains(&address)
                                {
                                    candidates.push(address);
                                }
                            }
                            Event::RpcTimedOut(request) => {
                                pending.remove(&request);
                            }
                            _ => {}
                        },
                    }
                }
                if pending.is_empty() {
                    break;
                }
                let wake = core.poll_timeout().map_or(deadline, |at| {
                    (tokio::time::Instant::now()
                        + Duration::from_millis(at.saturating_sub(time(start).monotonic_ms)))
                    .min(deadline)
                });
                tokio::select! {
                    received = socket.recv_from(&mut bytes) => {
                        match received {
                            Ok((len, from)) => {
                                let from = translation.source(from);
                                if address_filter(from) {
                                    if let Some(payload) = overlay.payload(&bytes[..len]) {
                                        actions = core.receive(from, payload, time(start));
                                    }
                                }
                            },
                            Err(error) if super::transient_receive_error(error.kind()) => {},
                            Err(error) => return Err(error),
                        }
                    }
                    _ = tokio::time::sleep_until(wake) => {
                        if tokio::time::Instant::now() >= deadline { break; }
                        actions = core.tick(time(start));
                    }
                }
            }
            observation.field("observed_candidates", Value::Count(candidates.len() as u64));
            observation.field("unanswered_reflectors", Value::Count(pending.len() as u64));
            observation.field("mapping_varies", Value::Flag(mapping_varies(&candidates)));
            if usable(local)
                && address_filter(translation.source(local))
                && !candidates.contains(&local)
            {
                candidates.push(local);
            }
            let mapping = match gateway {
                Some(gateway) => MappingLease::acquire(gateway, local).await,
                None => None,
            };
            let mapping = mapping
                .filter(|(_, external)| address_filter(translation.source(*external)))
                .map(|(lease, external)| {
                    candidates.retain(|candidate| *candidate != external);
                    candidates.insert(0, external);
                    candidates.truncate(4);
                    lease
                });
            if candidates.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no usable data-socket candidates",
                ));
            }
            observation.field("gateway_mapping", Value::Flag(mapping.is_some()));
            observation.field("candidates", Value::Count(candidates.len() as u64));
            Ok(Self {
                observer,
                parent,
                socket,
                candidates,
                translation,
                mapping,
                address_filter,
            })
        }
        .await;
        observation.finish(result.as_ref().err().map(io_code).unwrap_or(""));
        result
    }
    pub fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }
    /// Simultaneously probe the authenticated peer's advertised candidates,
    /// then let the initiator nominate a single path for both endpoints.
    /// `None` is explicit direct-connect failure; this never selects a relay.
    pub async fn punch(
        self,
        peers: &[SocketAddr],
        config: &PunchConfig,
        session: [u8; 32],
        initiator: bool,
    ) -> io::Result<Option<DirectChannel>> {
        let mut observation = self.observer.child("nat.punch", self.parent);
        observation.field("initiator", Value::Flag(initiator));
        observation.field(
            "local_candidates",
            Value::Count(self.candidates.len() as u64),
        );
        observation.field("remote_candidates", Value::Count(peers.len() as u64));
        observation.field(
            "local_mapping_varies",
            Value::Flag(mapping_varies(&self.candidates)),
        );
        observation.field("remote_mapping_varies", Value::Flag(mapping_varies(peers)));
        observation.field("translation", Value::Text(self.translation.mode()));
        let result = async {
            if peers.is_empty() || peers.len() > 4 || peers.iter().any(|p| !usable(*p)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid candidate set",
                ));
            }
            let peers: Vec<_> = peers
                .iter()
                .map(|peer| self.translation.source(*peer))
                .filter(|peer| (self.address_filter)(*peer))
                .collect();
            if peers.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "all direct candidates are outside the address policy",
                ));
            }
            let peers = peers.as_slice();
            if let Some(mapping) = &self.mapping {
                mapping.check()?;
            }
            let strategy = if self.mapping.is_some() {
                puncher::NatStrategy::Direct
            } else {
                puncher::nat_strategy(mapping_varies(&self.candidates), mapping_varies(peers))
            };
            observation.field(
                "strategy",
                Value::Text(match strategy {
                    puncher::NatStrategy::Direct => "direct",
                    puncher::NatStrategy::OpenMappings => "open_mappings",
                    puncher::NatStrategy::SearchPorts => "search_ports",
                }),
            );
            let peers: Vec<_> = peers
                .iter()
                .map(|p| self.translation.destination(canonical(*p)))
                .collect();
            Ok(connect_channel(
                puncher::rendezvous_with_policy(
                    self.socket,
                    &peers,
                    config,
                    session,
                    initiator,
                    strategy,
                    &|address| (self.address_filter)(self.translation.source(address)),
                )
                .await?,
            )
            .await?
            .map(|channel| DirectChannel {
                channel,
                session,
                initiator,
                mapping: self.mapping,
            }))
        }
        .await;
        observation.finish(match &result {
            Ok(Some(_)) => "",
            Ok(None) => "direct_unreachable",
            Err(error) => io_code(error),
        });
        result
    }
}
fn mapping_varies(candidates: &[SocketAddr]) -> bool {
    candidates.iter().enumerate().any(|(i, a)| {
        candidates[i + 1..].iter().any(|b| {
            let a = canonical(*a);
            let b = canonical(*b);
            a.ip() == b.ip() && a.port() != b.port()
        })
    })
}
fn canonical(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map_or(address, |v4| SocketAddr::new(v4.into(), v6.port())),
        _ => address,
    }
}
fn usable(address: SocketAddr) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && match address.ip() {
            IpAddr::V4(ip) => !ip.is_broadcast(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        }
}

/// A nominated path that continues answering session-bound probes and
/// nominations during Noise. Reserved WPN1 control packets never surface as data.
pub struct DirectChannel {
    channel: Channel,
    session: [u8; 32],
    initiator: bool,
    mapping: Option<MappingLease>,
}
impl DirectChannel {
    pub fn peer(&self) -> SocketAddr {
        self.channel.peer()
    }
    pub async fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(mapping) = &self.mapping {
            mapping.check()?;
        }
        self.channel.send(bytes).await
    }
    pub async fn recv(&self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive buffer too small",
            ));
        }
        loop {
            let len = tokio::select! {
                biased;
                _ = async { if let Some(mapping) = &self.mapping { mapping.expired().await; } else { std::future::pending::<()>().await; } } => return Err(super::mapping::expired()),
                result = self.channel.recv(bytes) => result?,
            };
            if bytes[..len].starts_with(b"WPN1") {
                if let Some(reply) =
                    puncher::rendezvous_reply(&bytes[..len], self.session, self.initiator)
                {
                    self.channel.send(&reply).await?;
                }
            } else {
                return Ok(len);
            }
        }
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    #[tokio::test]
    async fn regional_reflection_is_required_for_wildcard_bound_candidates() {
        let overlay = OverlayId::regional("reflection-test");
        let reflector = super::super::Node::bind_in_overlay(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::generate(),
            true,
            dht_next::RoutingPolicy::Unrestricted,
            overlay,
        )
        .await
        .unwrap();
        let node = super::super::Node::bind_filtered(
            "0.0.0.0:0".parse().unwrap(),
            Keypair::generate(),
            false,
            dht_next::RoutingPolicy::Unrestricted,
            overlay,
            std::sync::Arc::new(|address| address.ip().is_loopback()),
        )
        .await
        .unwrap();
        let direct = node
            .direct_socket(
                &[Contact::new(reflector.id(), reflector.local_addr())],
                None,
            )
            .await
            .unwrap();
        // A wildcard bind has no usable local fallback: this must be reflected.
        assert!(direct.socket.local_addr().unwrap().ip().is_unspecified());
        assert_eq!(
            direct.candidates(),
            &[SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                direct.socket.local_addr().unwrap().port()
            )]
        );
        drop(direct);
        node.shutdown().await.unwrap();
        reflector.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn reflection_rejects_wrong_overlay_and_never_contacts_denied_reflectors() {
        let overlay = OverlayId::regional("expected");
        let wrong = super::super::Node::bind_in_overlay(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::generate(),
            true,
            dht_next::RoutingPolicy::Unrestricted,
            OverlayId::regional("wrong"),
        )
        .await
        .unwrap();
        let denied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let denied_address = denied.local_addr().unwrap();
        let node = super::super::Node::bind_filtered(
            "0.0.0.0:0".parse().unwrap(),
            Keypair::generate(),
            false,
            dht_next::RoutingPolicy::Unrestricted,
            overlay,
            std::sync::Arc::new(move |address| address != denied_address),
        )
        .await
        .unwrap();
        let result = node
            .direct_socket(
                &[
                    Contact::new(dht_next::NodeId::from_bytes([93; 32]), denied_address),
                    Contact::new(wrong.id(), wrong.local_addr()),
                ],
                None,
            )
            .await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable));
        let mut bytes = [0; 1500];
        assert!(
            matches!(denied.try_recv_from(&mut bytes), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        node.shutdown().await.unwrap();
        wrong.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn direct_candidates_cannot_bypass_policy_with_ipv4_mapped_ipv6() {
        let denied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = denied.local_addr().unwrap();
        let node = super::super::Node::bind_filtered(
            "127.0.0.1:0".parse().unwrap(),
            Keypair::generate(),
            false,
            dht_next::RoutingPolicy::Unrestricted,
            OverlayId::regional("policy"),
            std::sync::Arc::new(move |peer| peer != address),
        )
        .await
        .unwrap();
        let direct = node.direct_socket(&[], None).await.unwrap();
        let mapped = SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(),
            address.port(),
        );
        let result = direct
            .punch(&[mapped], &PunchConfig::default(), [91; 32], true)
            .await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
        let mut bytes = [0; 1500];
        assert!(
            matches!(denied.try_recv_from(&mut bytes), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn reflection_tolerates_loss_and_two_slow_round_trips() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut core = Dht::new(Keypair::from_seed(&[235; 32]), [236; 32], true);
        let reflector = Contact::new(core.id(), server.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let start = Instant::now();
            let mut buf = [0; 1201];
            let _ = server.recv_from(&mut buf).await.unwrap();
            loop {
                let (n, from) = server.recv_from(&mut buf).await.unwrap();
                let actions = core.receive(from, &buf[..n], time(start));
                tokio::time::sleep(Duration::from_millis(400)).await;
                for action in actions {
                    if let Action::Send { to, bytes } = action {
                        server.send_to(&bytes, to).await.unwrap();
                    }
                }
            }
        });
        let direct = DirectSocket::bind("0.0.0.0:0".parse().unwrap(), &[reflector])
            .await
            .unwrap();
        assert!(!direct.candidates().is_empty());
        assert!(direct.candidates()[0].ip().is_loopback());
        task.abort();
    }
}
