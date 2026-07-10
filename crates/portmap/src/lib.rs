//! Port mapping via **PCP** (Port Control Protocol, RFC 6887) — asking the local
//! gateway to open an external UDP port that forwards to us.
//!
//! Warren connects by hole punching, and learns a punchable external address
//! reflexively (a STUN-like probe). Port mapping is a *complementary* path: on a
//! gateway that speaks PCP (many home routers do, often alongside NAT-PMP/UPnP),
//! a peer can ask for a stable external `ip:port` that forwards inbound UDP to its
//! socket — so it becomes directly reachable without a punch, raising
//! direct-connect success and helping the hard symmetric-NAT case.
//!
//! The wire format is the verified, sans-IO core: [`MapRequest`] / [`MapResponse`]
//! encode and decode PCP's fixed 60-byte MAP messages, so the codec is
//! known-answer- and round-trip-tested with no sockets. [`map_port`] is the thin
//! I/O layer: it sends a MAP request to the gateway and awaits the response, with
//! retransmission (the request is a datagram and may be lost) and a mapping nonce
//! that a spoofed or stale reply can't match.
//!
//! PCP was chosen over UPnP-IGD (SOAP/XML over HTTP — heavy to parse) for the same
//! reason the rest of the stack uses compact binary formats: it is a small,
//! fixed-layout protocol that is cleanly verifiable.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

mod upnp;
pub use upnp::{map_port_upnp, UpnpError};

/// The PCP (and NAT-PMP) server port on the gateway.
pub const PCP_PORT: u16 = 5351;

/// Time budget for the PCP attempt in [`map_port_auto`] before falling back to
/// UPnP. Short: an unsupported gateway usually refuses immediately, and we don't
/// want to sit through PCP's full retransmit budget when UPnP is the real path.
const PCP_ATTEMPT: Duration = Duration::from_secs(1);

/// An error from the combined [`map_port_auto`] path.
#[derive(Debug, Error)]
pub enum MapError {
    /// No port-mapping gateway was found on the network (SSDP got no response).
    #[error("no port-mapping gateway found on the network")]
    NoGateway,
    /// A gateway was found and PCP was tried, but the UPnP fallback failed.
    #[error("PCP unavailable and UPnP fallback failed: {0}")]
    Upnp(UpnpError),
}

/// Map an external UDP port to `internal_port`, trying **PCP first and UPnP-IGD as
/// a fallback**, in one call. Discovers the gateway by SSDP — which finds the IGD
/// and, from its device-description URL, its IP — then tries PCP against that
/// gateway (the lean binary protocol, one exchange). If PCP doesn't answer within
/// a short attempt window, falls back to UPnP against the same device.
/// `description` labels the mapping in the router's UI (UPnP only; PCP carries no
/// label).
///
/// A gateway that speaks PCP but *not* UPnP won't be found — SSDP is the only
/// portable gateway discovery available here — but that combination is rare on
/// consumer routers, which is where port mapping matters.
///
/// # Panics
///
/// Panics only if the OS entropy source is unavailable (via [`map_port`]).
pub async fn map_port_auto(
    internal_port: u16,
    lifetime: Duration,
    description: &str,
) -> Result<Mapping, MapError> {
    let location = match upnp::discover_location().await {
        Ok(location) => location,
        Err(UpnpError::NoGateway) => return Err(MapError::NoGateway),
        Err(e) => return Err(MapError::Upnp(e)),
    };
    map_via_gateway(&location, internal_port, lifetime, description).await
}

/// The testable core of [`map_port_auto`]: given the gateway's device-description
/// URL, try PCP at that host, then fall back to UPnP against the same URL.
async fn map_via_gateway(
    location: &str,
    internal_port: u16,
    lifetime: Duration,
    description: &str,
) -> Result<Mapping, MapError> {
    // The device-description host is the gateway's IP — the PCP server too, if it
    // speaks PCP. Try that lean path first; on any failure (refused, timeout,
    // no IP-literal host) fall through to UPnP.
    if let Some((host, _, _)) = upnp::parse_url(location) {
        if let Ok(ip) = host.parse::<IpAddr>() {
            let gateway = SocketAddr::new(ip, PCP_PORT);
            if let Ok(Ok(mapping)) =
                timeout(PCP_ATTEMPT, map_port(gateway, internal_port, lifetime)).await
            {
                return Ok(mapping);
            }
        }
    }
    upnp::map_via_location(location, internal_port, lifetime, description)
        .await
        .map_err(MapError::Upnp)
}

/// PCP version 2 (RFC 6887).
const VERSION: u8 = 2;
/// The MAP opcode.
const OPCODE_MAP: u8 = 1;
/// High bit of the opcode octet, set on responses (`R`).
const RESPONSE_BIT: u8 = 0x80;
/// IANA protocol number for UDP.
const PROTO_UDP: u8 = 17;
/// Result code for a successful mapping.
const RESULT_SUCCESS: u8 = 0;
/// A MAP message (common header + MAP opcode data) is exactly this many bytes.
const MSG_LEN: usize = 60;
/// Length of the anti-spoofing mapping nonce.
const NONCE_LEN: usize = 12;

/// How many times [`map_port`] sends the request before giving up.
const ATTEMPTS: u32 = 4;

/// Errors from requesting a port mapping.
#[derive(Debug, Error)]
pub enum PcpError {
    /// A socket error sending to or receiving from the gateway.
    #[error("port-mapping I/O error: {0}")]
    Io(#[from] io::Error),
    /// The gateway never sent a valid response within the retransmit budget.
    #[error("port-mapping request timed out")]
    Timeout,
    /// A response was too short, or not a PCP MAP response.
    #[error("malformed PCP response")]
    Malformed,
    /// The gateway refused the mapping (a non-success PCP result code).
    #[error("gateway rejected the mapping (PCP result code {0})")]
    Rejected(u8),
}

/// A PCP MAP request: ask the gateway to map an external port to `internal_port`
/// on the client (`client_ip`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapRequest {
    /// Random nonce echoed in the response, so a spoofed/stale reply can't match.
    pub nonce: [u8; NONCE_LEN],
    /// IANA protocol number (17 = UDP).
    pub protocol: u8,
    /// The internal (local) port to map.
    pub internal_port: u16,
    /// A preferred external port, or 0 for "no preference".
    pub suggested_external_port: u16,
    /// A preferred external IP, or unspecified for "no preference".
    pub suggested_external_ip: Ipv6Addr,
    /// Requested lifetime of the mapping, in seconds.
    pub lifetime: u32,
    /// The client's own (internal) address, IPv4 written as IPv4-mapped IPv6.
    pub client_ip: Ipv6Addr,
}

impl MapRequest {
    /// A UDP MAP request for `internal_port` on `client_ip`, with no preferred
    /// external port/IP.
    pub fn map_udp(
        nonce: [u8; NONCE_LEN],
        internal_port: u16,
        lifetime: u32,
        client_ip: Ipv6Addr,
    ) -> Self {
        Self {
            nonce,
            protocol: PROTO_UDP,
            internal_port,
            suggested_external_port: 0,
            suggested_external_ip: Ipv6Addr::UNSPECIFIED,
            lifetime,
            client_ip,
        }
    }

    /// Encode to the 60-byte PCP MAP request wire format.
    pub fn encode(&self) -> [u8; MSG_LEN] {
        let mut b = [0u8; MSG_LEN];
        b[0] = VERSION;
        b[1] = OPCODE_MAP; // R = 0 for a request
        b[4..8].copy_from_slice(&self.lifetime.to_be_bytes());
        b[8..24].copy_from_slice(&self.client_ip.octets());
        b[24..36].copy_from_slice(&self.nonce);
        b[36] = self.protocol;
        b[40..42].copy_from_slice(&self.internal_port.to_be_bytes());
        b[42..44].copy_from_slice(&self.suggested_external_port.to_be_bytes());
        b[44..60].copy_from_slice(&self.suggested_external_ip.octets());
        b
    }

    /// Decode a PCP MAP request (the gateway/server side of the protocol).
    pub fn decode(buf: &[u8]) -> Result<Self, PcpError> {
        let b = check_header(buf, OPCODE_MAP)?;
        Ok(Self {
            lifetime: u32::from_be_bytes(b[4..8].try_into().unwrap()),
            client_ip: ipv6_at(b, 8),
            nonce: b[24..36].try_into().unwrap(),
            protocol: b[36],
            internal_port: u16::from_be_bytes(b[40..42].try_into().unwrap()),
            suggested_external_port: u16::from_be_bytes(b[42..44].try_into().unwrap()),
            suggested_external_ip: ipv6_at(b, 44),
        })
    }
}

/// A PCP MAP response from the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapResponse {
    /// 0 = success; anything else is a rejection.
    pub result_code: u8,
    /// Granted lifetime of the mapping, in seconds.
    pub lifetime: u32,
    /// The gateway's epoch time (used to detect a gateway reboot; not used here).
    pub epoch: u32,
    /// Echoed request nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Protocol of the mapping.
    pub protocol: u8,
    /// The internal port that was mapped.
    pub internal_port: u16,
    /// The assigned external port.
    pub external_port: u16,
    /// The assigned external IP (IPv4-mapped IPv6 for an IPv4 gateway).
    pub external_ip: Ipv6Addr,
}

impl MapResponse {
    /// Encode to the 60-byte PCP MAP response wire format (the gateway side).
    pub fn encode(&self) -> [u8; MSG_LEN] {
        let mut b = [0u8; MSG_LEN];
        b[0] = VERSION;
        b[1] = RESPONSE_BIT | OPCODE_MAP;
        b[3] = self.result_code;
        b[4..8].copy_from_slice(&self.lifetime.to_be_bytes());
        b[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        b[24..36].copy_from_slice(&self.nonce);
        b[36] = self.protocol;
        b[40..42].copy_from_slice(&self.internal_port.to_be_bytes());
        b[42..44].copy_from_slice(&self.external_port.to_be_bytes());
        b[44..60].copy_from_slice(&self.external_ip.octets());
        b
    }

    /// Decode a PCP MAP response, rejecting anything that isn't one.
    pub fn decode(buf: &[u8]) -> Result<Self, PcpError> {
        let b = check_header(buf, RESPONSE_BIT | OPCODE_MAP)?;
        Ok(Self {
            result_code: b[3],
            lifetime: u32::from_be_bytes(b[4..8].try_into().unwrap()),
            epoch: u32::from_be_bytes(b[8..12].try_into().unwrap()),
            nonce: b[24..36].try_into().unwrap(),
            protocol: b[36],
            internal_port: u16::from_be_bytes(b[40..42].try_into().unwrap()),
            external_port: u16::from_be_bytes(b[42..44].try_into().unwrap()),
            external_ip: ipv6_at(b, 44),
        })
    }
}

/// A granted mapping: the external address inbound traffic can now reach, and how
/// long the gateway will hold it (renew before it expires).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// The external `ip:port` that forwards to the mapped internal port.
    pub external: SocketAddr,
    /// How long the mapping lasts before it must be renewed.
    pub lifetime: Duration,
}

/// Validate the fixed header and length, returning the first [`MSG_LEN`] bytes.
/// `opcode_byte` is the expected value of byte 1 — the R-bit-plus-opcode octet
/// (the opcode alone for a request, or ORed with the response bit for a response).
fn check_header(buf: &[u8], opcode_byte: u8) -> Result<&[u8], PcpError> {
    if buf.len() < MSG_LEN || buf[0] != VERSION || buf[1] != opcode_byte {
        return Err(PcpError::Malformed);
    }
    Ok(&buf[..MSG_LEN])
}

/// The 16-byte IPv6 address at offset `at` in a (length-checked) buffer.
fn ipv6_at(b: &[u8], at: usize) -> Ipv6Addr {
    let octets: [u8; 16] = b[at..at + 16].try_into().unwrap();
    Ipv6Addr::from(octets)
}

/// Represent any IP as the 16-byte form PCP carries (IPv4 as IPv4-mapped IPv6).
fn as_v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// A fresh random mapping nonce.
fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("OS entropy source unavailable");
    nonce
}

/// Ask `gateway` (a PCP server, typically the default gateway at [`PCP_PORT`]) to
/// map an external UDP port to `internal_port` on this host, for up to `lifetime`.
/// The client address in the request is derived by routing to the gateway (see
/// below), so the caller only supplies the port to map. Returns the assigned
/// external address on success.
///
/// The request is retransmitted with exponential backoff (it's a lone datagram),
/// and only a response carrying our nonce, from the gateway, is accepted — so a
/// spoofed or stale reply is ignored. A non-success result code is surfaced as
/// [`PcpError::Rejected`].
///
/// # Panics
///
/// Panics only if the OS entropy source is unavailable (needed for the mapping
/// nonce), which is unrecoverable.
pub async fn map_port(
    gateway: SocketAddr,
    internal_port: u16,
    lifetime: Duration,
) -> Result<Mapping, PcpError> {
    // Bind to the unspecified address of the gateway's family and `connect`, so
    // the OS picks the source IP of the interface that actually routes to the
    // gateway. That source IP is the client address PCP wants in the request — a
    // caller's own `local.ip()` might be a wildcard (`0.0.0.0`/`[::]`, which a
    // gateway rejects) or the wrong interface on a multi-homed host. Connecting
    // also filters received datagrams to the gateway for us.
    let unspecified = if gateway.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let sock = UdpSocket::bind(SocketAddr::new(unspecified, 0)).await?;
    sock.connect(gateway).await?;
    let client_ip = as_v6(sock.local_addr()?.ip());

    let nonce = random_nonce();
    // Clamp to at least 1s: PCP reads a zero lifetime as "delete the mapping", so
    // a sub-second `lifetime` (which `as_secs` would truncate to 0) must not turn
    // a map request into an unmap.
    let secs = lifetime.as_secs().clamp(1, u32::MAX as u64) as u32;
    let request = MapRequest::map_udp(nonce, internal_port, secs, client_ip).encode();

    let mut buf = [0u8; 1100];
    for attempt in 0..ATTEMPTS {
        sock.send(&request).await?;
        // Backoff 250ms, 500ms, 1s, ... between retransmits.
        let wait = Duration::from_millis(250u64 << attempt);
        match timeout(wait, recv_matching(&sock, &mut buf, &nonce)).await {
            Ok(Ok(resp)) => {
                if resp.result_code != RESULT_SUCCESS {
                    return Err(PcpError::Rejected(resp.result_code));
                }
                let ip = resp
                    .external_ip
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(resp.external_ip));
                return Ok(Mapping {
                    external: SocketAddr::new(ip, resp.external_port),
                    lifetime: Duration::from_secs(resp.lifetime as u64),
                });
            }
            Ok(Err(e)) => return Err(e), // socket error — not recoverable by retrying
            Err(_) => continue,          // no answer in time — retransmit
        }
    }
    Err(PcpError::Timeout)
}

/// Receive datagrams (from the connected gateway) until one is a PCP MAP response
/// carrying `nonce`, ignoring anything else (a stray or replayed packet).
async fn recv_matching(
    sock: &UdpSocket,
    buf: &mut [u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<MapResponse, PcpError> {
    loop {
        let n = sock.recv(buf).await?; // connected: only the gateway's datagrams
        if let Ok(resp) = MapResponse::decode(&buf[..n]) {
            if resp.nonce == *nonce {
                return Ok(resp);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_request() -> MapRequest {
        MapRequest::map_udp(
            [7u8; NONCE_LEN],
            40001,
            3600,
            Ipv4Addr::new(192, 168, 1, 50).to_ipv6_mapped(),
        )
    }

    #[test]
    fn request_encodes_the_pcp_wire_format() {
        let b = sample_request().encode();
        assert_eq!(b.len(), MSG_LEN);
        assert_eq!(b[0], VERSION);
        assert_eq!(b[1], OPCODE_MAP); // request: response bit clear
        assert_eq!(u32::from_be_bytes(b[4..8].try_into().unwrap()), 3600);
        assert_eq!(&b[24..36], &[7u8; NONCE_LEN]);
        assert_eq!(b[36], PROTO_UDP);
        assert_eq!(u16::from_be_bytes(b[40..42].try_into().unwrap()), 40001);
    }

    #[test]
    fn request_roundtrips() {
        let req = sample_request();
        assert_eq!(MapRequest::decode(&req.encode()).unwrap(), req);
    }

    #[test]
    fn response_roundtrips() {
        let resp = MapResponse {
            result_code: RESULT_SUCCESS,
            lifetime: 7200,
            epoch: 123456,
            nonce: [9u8; NONCE_LEN],
            protocol: PROTO_UDP,
            internal_port: 40001,
            external_port: 51000,
            external_ip: Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped(),
        };
        assert_eq!(MapResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn decode_rejects_malformed() {
        // Too short.
        assert!(matches!(
            MapResponse::decode(&[0u8; 10]),
            Err(PcpError::Malformed)
        ));
        // Right length, wrong version.
        let mut b = MapResponse {
            result_code: 0,
            lifetime: 1,
            epoch: 0,
            nonce: [0; NONCE_LEN],
            protocol: PROTO_UDP,
            internal_port: 1,
            external_port: 2,
            external_ip: Ipv6Addr::UNSPECIFIED,
        }
        .encode();
        b[0] = 99;
        assert!(matches!(MapResponse::decode(&b), Err(PcpError::Malformed)));
        // A request is not a response (opcode byte lacks the response bit).
        assert!(matches!(
            MapResponse::decode(&sample_request().encode()),
            Err(PcpError::Malformed)
        ));
    }

    proptest! {
        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let _ = MapRequest::decode(&bytes);
            let _ = MapResponse::decode(&bytes);
        }
    }

    #[tokio::test]
    async fn map_port_completes_against_a_gateway() {
        // A fake PCP gateway: read the MAP request, reply with a success response
        // that echoes the nonce and grants an external ip:port.
        let gw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw.local_addr().unwrap();
        let external = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 51001);

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 1100];
            let (n, from) = gw.recv_from(&mut buf).await.unwrap();
            let req = MapRequest::decode(&buf[..n]).expect("valid MAP request");
            let resp = MapResponse {
                result_code: RESULT_SUCCESS,
                lifetime: req.lifetime,
                epoch: 1,
                nonce: req.nonce, // echo
                protocol: req.protocol,
                internal_port: req.internal_port,
                external_port: external.port(),
                external_ip: as_v6(external.ip()),
            };
            gw.send_to(&resp.encode(), from).await.unwrap();
        });

        let mapping = map_port(gw_addr, 40002, Duration::from_secs(3600))
            .await
            .expect("mapping should succeed");
        assert_eq!(mapping.external, external);
        assert_eq!(mapping.lifetime, Duration::from_secs(3600));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn map_port_surfaces_a_rejection() {
        // A gateway that refuses (non-zero result code) — surfaced, not retried.
        let gw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1100];
            let (n, from) = gw.recv_from(&mut buf).await.unwrap();
            let req = MapRequest::decode(&buf[..n]).unwrap();
            let resp = MapResponse {
                result_code: 8, // NO_RESOURCES
                lifetime: 0,
                epoch: 1,
                nonce: req.nonce,
                protocol: req.protocol,
                internal_port: req.internal_port,
                external_port: 0,
                external_ip: Ipv6Addr::UNSPECIFIED,
            };
            gw.send_to(&resp.encode(), from).await.unwrap();
        });

        let err = map_port(gw_addr, 40003, Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(matches!(err, PcpError::Rejected(8)));
    }

    /// A tiny fake IGD (device XML + AddPortMapping/GetExternalIPAddress SOAP),
    /// serving one request per `Connection: close` socket. Returns its address.
    async fn fake_igd(external_ip: &str) -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let external_ip = external_ip.to_string();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let text = String::from_utf8_lossy(&buf);
                    if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                        let need = head
                            .lines()
                            .find_map(|l| {
                                l.split_once(':')
                                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            })
                            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if rest.len() >= need {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf);
                let body = if text.starts_with("GET ") {
                    r#"<?xml version="1.0"?><root><device><serviceList><service>
                    <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                    <controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>"#
                        .to_string()
                } else if text.contains("GetExternalIPAddress") {
                    format!(
                        "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>\
                         <NewExternalIPAddress>{external_ip}</NewExternalIPAddress>\
                         </u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
                    )
                } else {
                    "<s:Envelope><s:Body><u:AddPortMappingResponse></u:AddPortMappingResponse></s:Body></s:Envelope>".to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn map_via_gateway_falls_back_to_upnp_when_pcp_is_silent() {
        // PCP is tried at the gateway host:5351 (nothing there on loopback, so it
        // fails fast), then the UPnP fallback maps against the fake IGD. This
        // exercises the fallback arm of the combined path; the PCP-success arm is
        // covered by `map_port_completes_against_a_gateway`.
        let igd = fake_igd("203.0.113.77").await;
        let location = format!("http://{igd}/rootDesc.xml");
        let mapping = map_via_gateway(&location, 40004, Duration::from_secs(3600), "warren")
            .await
            .expect("UPnP fallback should map");
        assert_eq!(
            mapping.external,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)), 40004)
        );
    }
}
