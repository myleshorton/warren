//! NAT64 is local socket routing, never a rewrite of authenticated DHT records.
use std::io;
#[cfg(not(target_vendor = "apple"))]
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Prefix {
    bytes: [u8; 16],
    length: usize,
}
impl Prefix {
    fn positions(&self) -> impl Iterator<Item = usize> + '_ {
        let start = self.length / 8;
        (start..16)
            .filter(move |i| self.length == 96 || *i != 8)
            .take(4)
    }
    fn embed(&self, ip: Ipv4Addr) -> Ipv6Addr {
        let mut bytes = self.bytes;
        for (position, byte) in self.positions().zip(ip.octets()) {
            bytes[position] = byte;
        }
        bytes.into()
    }
    fn extract(&self, ip: Ipv6Addr) -> Option<Ipv4Addr> {
        let bytes = ip.octets();
        let mut ipv4 = [0; 4];
        for (index, position) in self.positions().enumerate() {
            ipv4[index] = bytes[position];
        }
        let ipv4 = Ipv4Addr::from(ipv4);
        (self.embed(ipv4) == ip).then_some(ipv4)
    }
    fn from_probe(address: Ipv6Addr, probe: Ipv4Addr) -> Option<Self> {
        let mut matches = Vec::new();
        for length in [32, 40, 48, 56, 64, 96] {
            let mut bytes = address.octets();
            bytes[length / 8..].fill(0);
            let prefix = Self { bytes, length };
            if prefix.embed(probe) == address {
                matches.push(prefix);
            }
        }
        (matches.len() == 1).then(|| matches.remove(0))
    }
}

fn prefixes(addresses: impl IntoIterator<Item = IpAddr>) -> Vec<Prefix> {
    let mut found = Vec::new();
    for address in addresses {
        let IpAddr::V6(ip) = address else { continue };
        if ip.to_ipv4_mapped().is_some() {
            continue;
        }
        for probe in [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)] {
            if let Some(prefix) = Prefix::from_probe(ip, probe) {
                if !found.contains(&prefix) && found.len() < 8 {
                    found.push(prefix);
                }
            }
        }
    }
    found
}

#[cfg(target_vendor = "apple")]
fn system_addresses(host: &str) -> io::Result<Vec<IpAddr>> {
    use std::ffi::CString;
    let host = CString::new(host).map_err(|_| io::Error::other("invalid address"))?;
    // AI_DEFAULT enables Apple's IPv4-literal synthesis on IPv6-only interfaces.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_DGRAM;
    hints.ai_flags = libc::AI_DEFAULT;
    let mut head = std::ptr::null_mut();
    let error = unsafe { libc::getaddrinfo(host.as_ptr(), std::ptr::null(), &hints, &mut head) };
    if error != 0 {
        return Err(io::Error::other(format!("getaddrinfo failed: {error}")));
    }
    let mut addresses = Vec::new();
    let mut entry = head;
    while !entry.is_null() {
        let info = unsafe { &*entry };
        if !info.ai_addr.is_null() {
            if info.ai_family == libc::AF_INET6 {
                let addr = unsafe { &*(info.ai_addr as *const libc::sockaddr_in6) };
                addresses.push(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)));
            } else if info.ai_family == libc::AF_INET {
                let addr = unsafe { &*(info.ai_addr as *const libc::sockaddr_in) };
                addresses.push(IpAddr::V4(Ipv4Addr::from(
                    addr.sin_addr.s_addr.to_ne_bytes(),
                )));
            }
        }
        entry = info.ai_next;
    }
    unsafe { libc::freeaddrinfo(head) };
    Ok(addresses)
}

#[cfg(not(target_vendor = "apple"))]
fn system_addresses(host: &str) -> io::Result<Vec<IpAddr>> {
    Ok((host, 0)
        .to_socket_addrs()?
        .map(|address| address.ip())
        .collect())
}

fn discover() -> io::Result<Vec<Prefix>> {
    #[cfg(target_vendor = "apple")]
    let addresses = system_addresses("192.0.0.170")?;
    #[cfg(not(target_vendor = "apple"))]
    let addresses = system_addresses("ipv4only.arpa.")?;
    Ok(prefixes(addresses))
}

/// Candidate socket destinations for a numeric bootstrap. May block in the OS
/// resolver; call off the UI/async executor thread. No fixed NAT64 prefix is assumed.
pub fn route_addresses(address: SocketAddr) -> io::Result<Vec<SocketAddr>> {
    if address.is_ipv6() || address.ip().is_loopback() {
        return Ok(vec![address]);
    }
    #[cfg(target_vendor = "apple")]
    {
        Ok(system_addresses(&address.ip().to_string())?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, address.port()))
            .collect())
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        if socket.connect(address).is_ok() {
            return Ok(vec![address]);
        }
        let IpAddr::V4(ip) = address.ip() else {
            unreachable!()
        };
        Ok(discover()?
            .into_iter()
            .map(|prefix| SocketAddr::new(prefix.embed(ip).into(), address.port()))
            .collect())
    }
}

#[derive(Clone, Debug)]
pub(super) struct Translation {
    bind: SocketAddr,
    prefixes: Vec<Prefix>,
}
impl Translation {
    pub async fn discover(bind: SocketAddr) -> Self {
        Self::with_discovery(bind, async {
            tokio::task::spawn_blocking(discover)
                .await
                .map_err(io::Error::other)?
        })
        .await
    }
    async fn with_discovery(
        bind: SocketAddr,
        lookup: impl std::future::Future<Output = io::Result<Vec<Prefix>>>,
    ) -> Self {
        let prefixes = if bind.is_ipv6() && !bind.ip().is_loopback() {
            tokio::time::timeout(std::time::Duration::from_secs(5), lookup)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default()
        } else {
            vec![]
        };
        Self { bind, prefixes }
    }
    pub fn destination(&self, address: SocketAddr) -> SocketAddr {
        match (self.bind.is_ipv6(), address) {
            (true, SocketAddr::V4(v4)) => {
                if let Some(prefix) = self.prefixes.first() {
                    return SocketAddr::new(prefix.embed(*v4.ip()).into(), v4.port());
                }
                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
            }
            _ => address,
        }
    }
    pub fn source(&self, address: SocketAddr) -> SocketAddr {
        let SocketAddr::V6(v6) = address else {
            return address;
        };
        v6.ip()
            .to_ipv4_mapped()
            .or_else(|| {
                self.prefixes
                    .iter()
                    .find_map(|prefix| prefix.extract(*v6.ip()))
            })
            .map_or(address, |ip| SocketAddr::new(ip.into(), address.port()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn unavailable_synthesis_preserves_native_ipv6() {
        let bind = "[2001:db8::1]:1234".parse().unwrap();
        let peer = "[2001:db8::2]:4321".parse().unwrap();
        let timed_out = Translation::with_discovery(bind, std::future::pending()).await;
        let failed =
            Translation::with_discovery(bind, async { Err(io::Error::other("DNS unavailable")) })
                .await;
        for translation in [timed_out, failed] {
            assert!(translation.prefixes.is_empty());
            assert_eq!(translation.destination(peer), peer);
            assert_eq!(translation.source(peer), peer);
        }
    }

    #[test]
    fn rfc6052_layouts_round_trip_and_do_not_rewrite_other_ipv6() {
        let examples = [
            (32, "2001:db8:c000:221::"),
            (40, "2001:db8:c0:2:21::"),
            (48, "2001:db8:0:c000:2:2100::"),
            (56, "2001:db8:0:c0:0:221::"),
            (64, "2001:db8::c0:2:2100:0"),
            (96, "2001:db8::c000:221"),
        ];
        for (length, expected) in examples {
            let prefix = Prefix {
                bytes: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(),
                length,
            };
            let ip = Ipv4Addr::new(192, 0, 2, 33);
            assert_eq!(prefix.embed(ip), expected.parse::<Ipv6Addr>().unwrap());
            assert_eq!(prefix.extract(prefix.embed(ip)), Some(ip));
            assert_eq!(prefix.extract("2001:db9::1".parse().unwrap()), None);
            let probe = Ipv4Addr::new(192, 0, 0, 170);
            assert_eq!(Prefix::from_probe(prefix.embed(probe), probe), Some(prefix));
        }
    }
    #[test]
    fn discovery_rejects_non_synthetic_answers_and_preserves_multiple_prefixes() {
        let a: IpAddr = "64:ff9b::c000:aa".parse().unwrap();
        let b: IpAddr = "2001:db8:64::c000:ab".parse().unwrap();
        let found = prefixes([
            a,
            a,
            b,
            "::ffff:192.0.0.170".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ]);
        assert_eq!(found.len(), 2);
        let transport = Translation {
            bind: "[::]:0".parse().unwrap(),
            prefixes: found,
        };
        assert_eq!(
            transport.source("[64:ff9b::c000:201]:41800".parse().unwrap()),
            "192.0.2.1:41800".parse().unwrap()
        );
        let native = "[2001:db8::1]:41800".parse().unwrap();
        assert_eq!(transport.source(native), native);
    }
}
