//! Candidate gathering on the exact socket later used for the data connection.
use super::{mapping::MappingLease, time};
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
    socket: UdpSocket,
    candidates: Vec<SocketAddr>,
    dual_stack: bool,
    mapping: Option<MappingLease>,
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
        let socket = super::bind_socket(bind)?;
        let local = canonical(socket.local_addr()?);
        let dual_stack = bind.is_ipv6();
        let mut candidates = Vec::new();
        let mut core = Dht::new(Keypair::generate(), Keypair::generate().seed(), false);
        let start = Instant::now();
        let mut pending = BTreeSet::new();
        let mut actions = Vec::new();
        for peer in reflectors.iter().take(3) {
            if let Ok((request, sent)) = core.reflect(*peer, time(start)) {
                pending.insert(request);
                actions.extend(sent);
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        let mut bytes = [0; dht_next::protocol::MAX_PACKET + 1];
        loop {
            for action in actions.drain(..) {
                match action {
                    Action::Send { to, bytes } => {
                        let _ = socket.send_to(&bytes, destination(to, dual_stack)).await;
                    }
                    Action::Event(event) => match *event {
                        Event::ObservedAddress {
                            request, address, ..
                        } if pending.remove(&request) => {
                            let address = canonical(address);
                            if usable(address)
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
                        Ok((len, from)) => actions = core.receive(canonical(from), &bytes[..len], time(start)),
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
        if usable(local) && !candidates.contains(&local) {
            candidates.push(local);
        }
        let mapping = match gateway {
            Some(gateway) => MappingLease::acquire(gateway, local).await,
            None => None,
        };
        let mapping = mapping.map(|(lease, external)| {
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
        Ok(Self {
            socket,
            candidates,
            dual_stack,
            mapping,
        })
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
        if peers.is_empty() || peers.len() > 4 || peers.iter().any(|p| !usable(*p)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid candidate set",
            ));
        }
        if let Some(mapping) = &self.mapping {
            mapping.check()?;
        }
        let strategy = if self.mapping.is_some() {
            puncher::NatStrategy::Direct
        } else {
            puncher::nat_strategy(mapping_varies(&self.candidates), mapping_varies(peers))
        };
        let peers: Vec<_> = peers
            .iter()
            .map(|p| destination(canonical(*p), self.dual_stack))
            .collect();
        Ok(connect_channel(
            puncher::rendezvous_with_strategy(
                self.socket,
                &peers,
                config,
                session,
                initiator,
                strategy,
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
fn destination(address: SocketAddr, dual_stack: bool) -> SocketAddr {
    match (dual_stack, address) {
        (true, SocketAddr::V4(v4)) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
        _ => address,
    }
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
