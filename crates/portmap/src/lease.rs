use super::*;

/// Automatic discovery uses SSDP, with PCP first and UPnP as fallback. Explicit
/// PCP supports gateways without SSDP; explicit UPnP avoids discovery.
#[derive(Clone, Debug)]
pub enum Gateway {
    Automatic,
    Pcp(SocketAddr),
    Upnp(String),
}
/// Retains the gateway transaction needed to renew or remove a granted mapping.
pub enum Lease {
    Pcp(PcpLease),
    Upnp {
        location: String,
        internal: SocketAddr,
        lifetime: Duration,
    },
}
impl Lease {
    pub async fn acquire(
        gateway: &Gateway,
        internal: SocketAddr,
        lifetime: Duration,
    ) -> io::Result<(Self, Mapping)> {
        let location = match gateway {
            Gateway::Pcp(address) => {
                let mut lease = PcpLease::new(*address, internal, lifetime)
                    .await
                    .map_err(io::Error::other)?;
                let mapping = lease.renew().await.map_err(io::Error::other)?;
                return Ok((Self::Pcp(lease), mapping));
            }
            Gateway::Upnp(location) => location.clone(),
            Gateway::Automatic => upnp::discover_location().await.map_err(io::Error::other)?,
        };
        if matches!(gateway, Gateway::Automatic) {
            if let Some((host, _, _)) = upnp::parse_url(&location) {
                if let Ok(ip) = host.parse() {
                    if let Ok(Ok(result)) = timeout(PCP_ATTEMPT, async {
                        let mut lease =
                            PcpLease::new(SocketAddr::new(ip, PCP_PORT), internal, lifetime)
                                .await?;
                        let mapping = lease.renew().await?;
                        Ok::<_, PcpError>((Self::Pcp(lease), mapping))
                    })
                    .await
                    {
                        return Ok(result);
                    }
                }
            }
        }
        let mut lease = Self::Upnp {
            location,
            internal,
            lifetime,
        };
        let mapping = lease.renew().await?;
        Ok((lease, mapping))
    }
    pub async fn renew(&mut self) -> io::Result<Mapping> {
        match self {
            Self::Pcp(lease) => lease.renew().await.map_err(io::Error::other),
            Self::Upnp {
                location,
                internal,
                lifetime,
            } => upnp::map_for_socket(location, *internal, *lifetime, "Warren DHT data")
                .await
                .map_err(io::Error::other),
        }
    }
    pub async fn remove(&mut self) -> io::Result<()> {
        match self {
            Self::Pcp(lease) => lease.remove().await.map_err(io::Error::other),
            Self::Upnp {
                location, internal, ..
            } => upnp::remove_via_location(location, internal.port())
                .await
                .map_err(io::Error::other),
        }
    }
}
