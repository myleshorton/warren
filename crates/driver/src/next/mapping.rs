use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::{oneshot, watch};

pub(super) struct MappingLease {
    stop: Option<oneshot::Sender<()>>,
    valid: watch::Receiver<bool>,
}
impl Drop for MappingLease {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
impl MappingLease {
    pub(super) async fn acquire(
        gateway: &portmap::Gateway,
        internal: SocketAddr,
    ) -> Option<(Self, SocketAddr)> {
        let (mut lease, mapping) = tokio::time::timeout(
            Duration::from_secs(8),
            portmap::Lease::acquire(gateway, internal, Duration::from_secs(600)),
        )
        .await
        .ok()?
        .ok()?;
        // A mapping into another private/CGNAT network isn't a public candidate.
        let routable = match mapping.external.ip() {
            std::net::IpAddr::V4(_) => crate::is_publicly_routable(mapping.external.ip()),
            std::net::IpAddr::V6(ip) => {
                (ip.segments()[0] & 0xe000) == 0x2000
                    && !(ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
                    && !(ip.segments()[0] == 0x3fff && ip.segments()[1] & 0xf000 == 0)
            }
        };
        if !routable
            || (internal.is_ipv4() && mapping.external.is_ipv6())
            || mapping.external.port() == 0
            || mapping.lifetime.is_zero()
        {
            let _ = tokio::time::timeout(Duration::from_secs(1), lease.remove()).await;
            return None;
        }
        let (stop, mut stopped) = oneshot::channel();
        let (valid, receiver) = watch::channel(true);
        tokio::spawn(async move {
            let mut expires =
                tokio::time::Instant::now() + mapping.lifetime.min(Duration::from_secs(3600));
            let mut delay = mapping.lifetime.div_f64(2.0).min(Duration::from_secs(300));
            loop {
                let result = tokio::select! {
                    _ = &mut stopped => break,
                    _ = tokio::time::sleep_until(expires) => break,
                    result = async {
                        tokio::time::sleep(delay).await;
                        tokio::time::timeout(Duration::from_secs(4), lease.renew()).await
                    } => result,
                };
                match result {
                    Ok(Ok(next))
                        if next.external == mapping.external && !next.lifetime.is_zero() =>
                    {
                        expires = tokio::time::Instant::now()
                            + next.lifetime.min(Duration::from_secs(3600));
                        delay = next.lifetime.div_f64(2.0).min(Duration::from_secs(300));
                    }
                    Ok(Ok(_)) => break,
                    _ => delay = Duration::from_secs(1),
                }
            }
            valid.send_replace(false);
            let _ = tokio::time::timeout(Duration::from_secs(1), lease.remove()).await;
        });
        Some((
            Self {
                stop: Some(stop),
                valid: receiver,
            },
            mapping.external,
        ))
    }
    pub(super) async fn expired(&self) {
        let mut valid = self.valid.clone();
        loop {
            if !*valid.borrow() || valid.changed().await.is_err() {
                return;
            }
        }
    }
    pub(super) fn check(&self) -> io::Result<()> {
        if *self.valid.borrow() {
            Ok(())
        } else {
            Err(expired())
        }
    }
}
pub(super) fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "router mapping expired or changed; reconnect through DHT signaling",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;
    #[tokio::test]
    async fn candidate_gathering_maps_the_actual_wildcard_data_socket() {
        let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = gateway.local_addr().unwrap();
        let serving = tokio::spawn(async move {
            let mut bytes = [0; 128];
            let (len, from) = gateway.recv_from(&mut bytes).await.unwrap();
            let request = portmap::MapRequest::decode(&bytes[..len]).unwrap();
            assert_ne!(request.internal_port, 0);
            let response = portmap::MapResponse {
                result_code: 0,
                lifetime: 600,
                epoch: 1,
                nonce: request.nonce,
                protocol: 17,
                internal_port: request.internal_port,
                external_port: request.internal_port,
                external_ip: std::net::Ipv4Addr::new(8, 8, 4, 4).to_ipv6_mapped(),
            };
            gateway.send_to(&response.encode(), from).await.unwrap();
            let (len, from) = gateway.recv_from(&mut bytes).await.unwrap();
            let deleted = portmap::MapRequest::decode(&bytes[..len]).unwrap();
            assert_eq!(deleted.internal_port, request.internal_port);
            assert_eq!(deleted.lifetime, 0);
            gateway
                .send_to(
                    &portmap::MapResponse {
                        lifetime: 0,
                        ..response
                    }
                    .encode(),
                    from,
                )
                .await
                .unwrap();
            request.internal_port
        });
        let socket = super::super::DirectSocket::bind_with_mapping(
            "0.0.0.0:0".parse().unwrap(),
            &[],
            Some(&portmap::Gateway::Pcp(address)),
        )
        .await
        .unwrap();
        let candidate = socket.candidates()[0];
        assert_eq!(
            candidate.ip(),
            "8.8.4.4".parse::<std::net::IpAddr>().unwrap()
        );
        drop(socket);
        let mapped_port = tokio::time::timeout(Duration::from_secs(3), serving)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(candidate.port(), mapped_port);
    }
    #[tokio::test]
    async fn silent_gateway_expires_and_drop_requests_removal() {
        for stop_early in [false, true] {
            let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = gateway.local_addr().unwrap();
            let serving = tokio::spawn(async move {
                let mut bytes = [0; 128];
                let (len, from) = gateway.recv_from(&mut bytes).await.unwrap();
                let initial = portmap::MapRequest::decode(&bytes[..len]).unwrap();
                let response = portmap::MapResponse {
                    result_code: 0,
                    lifetime: 2,
                    epoch: 1,
                    nonce: initial.nonce,
                    protocol: 17,
                    internal_port: initial.internal_port,
                    external_port: 50000,
                    external_ip: std::net::Ipv4Addr::new(8, 8, 4, 4).to_ipv6_mapped(),
                };
                gateway.send_to(&response.encode(), from).await.unwrap();
                loop {
                    let (len, from) = gateway.recv_from(&mut bytes).await.unwrap();
                    let request = portmap::MapRequest::decode(&bytes[..len]).unwrap();
                    assert_eq!(request.nonce, initial.nonce);
                    if request.lifetime == 0 {
                        gateway
                            .send_to(
                                &portmap::MapResponse {
                                    lifetime: 0,
                                    ..response
                                }
                                .encode(),
                                from,
                            )
                            .await
                            .unwrap();
                        break;
                    }
                    // Renewals deliberately receive no response.
                }
            });
            let (lease, _) = MappingLease::acquire(
                &portmap::Gateway::Pcp(address),
                "127.0.0.1:12345".parse().unwrap(),
            )
            .await
            .unwrap();
            if !stop_early {
                tokio::time::timeout(Duration::from_secs(4), lease.expired())
                    .await
                    .unwrap();
                assert!(lease.check().is_err());
            }
            drop(lease);
            tokio::time::timeout(Duration::from_secs(4), serving)
                .await
                .unwrap()
                .unwrap();
        }
    }
    #[tokio::test]
    async fn changed_gateway_mapping_invalidates_the_path_and_is_removed() {
        let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = gateway.local_addr().unwrap();
        let serving = tokio::spawn(async move {
            let mut bytes = [0; 128];
            let mut nonce = None;
            for round in 0..3 {
                let (len, from) = gateway.recv_from(&mut bytes).await.unwrap();
                let request = portmap::MapRequest::decode(&bytes[..len]).unwrap();
                assert_eq!(request.internal_port, 12345);
                if let Some(nonce) = nonce {
                    assert_eq!(request.nonce, nonce);
                } else {
                    nonce = Some(request.nonce);
                }
                if round == 2 {
                    assert_eq!(request.lifetime, 0);
                }
                let response = portmap::MapResponse {
                    result_code: 0,
                    lifetime: if round == 2 { 0 } else { 2 },
                    epoch: if round == 0 { 100 } else { 0 },
                    nonce: request.nonce,
                    protocol: 17,
                    internal_port: request.internal_port,
                    external_port: if round == 0 { 50000 } else { 50001 },
                    external_ip: std::net::Ipv4Addr::new(8, 8, 4, 4).to_ipv6_mapped(),
                };
                gateway.send_to(&response.encode(), from).await.unwrap();
            }
        });
        let (lease, candidate) = MappingLease::acquire(
            &portmap::Gateway::Pcp(address),
            "127.0.0.1:12345".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(candidate.port(), 50000);
        assert!(lease.check().is_ok());
        tokio::time::timeout(Duration::from_secs(4), lease.expired())
            .await
            .unwrap();
        assert_eq!(
            lease.check().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        serving.await.unwrap();
    }
}
