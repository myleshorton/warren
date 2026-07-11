//! Port mapping via **UPnP-IGD** — for the many home gateways that speak UPnP
//! rather than PCP.
//!
//! Where PCP is one compact binary exchange, UPnP is a small stack of text
//! protocols, so this follows the crate's split: pure parsing/formatting helpers
//! (unit-tested against realistic payloads) under a thin I/O layer.
//!
//!  1. **Discover** — SSDP `M-SEARCH` (UDP multicast to `239.255.255.250:1900`);
//!     responders reply unicast with a `LOCATION:` URL for their device
//!     description. (We only *send* to the multicast group, so no group
//!     membership is needed; replies are unicast to our socket.)
//!  2. **Describe** — HTTP GET the LOCATION, and find the `WANIPConnection` /
//!     `WANPPPConnection` service's control URL in the device XML.
//!  3. **Map** — SOAP POST `AddPortMapping` (open an external UDP port to us) and
//!     `GetExternalIPAddress` (learn the address to advertise).
//!
//! The HTTP client and XML handling are deliberately minimal (no HTTP/XML crates,
//! matching the rest of the stack). Known limits, left as hardening: namespace-
//! prefixed device XML, chunked transfer-encoding, and IPv6 LOCATION URLs.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Instant};

use crate::Mapping;

/// SSDP multicast address and port.
const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
/// The device type we search for.
const IGD_DEVICE: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
/// The services that can add a port mapping (IGDv1), newest-preferred order.
const WAN_SERVICES: [&str; 2] = [
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];
/// How long to wait for an SSDP responder.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a single HTTP request to the gateway may take.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest complete HTTP response accepted from a gateway. Device descriptions
/// and SOAP replies are normally only a few KiB; this leaves ample compatibility
/// margin while preventing an untrusted LAN responder from growing memory without
/// bound by streaming until the timeout.
const MAX_HTTP_RESPONSE: usize = 1 << 20;

/// Errors from UPnP port mapping.
///
/// `#[non_exhaustive]` so adding a variant isn't a breaking change for downstream
/// exhaustive matches — callers must include a wildcard arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UpnpError {
    /// A socket/HTTP transport error.
    #[error("UPnP I/O error: {0}")]
    Io(#[from] io::Error),
    /// No IGD answered the SSDP search.
    #[error("no UPnP gateway found on the network")]
    NoGateway,
    /// The device description couldn't be understood (no usable WAN service).
    #[error("could not parse the gateway's device description")]
    BadDescription,
    /// The gateway returned a non-200 HTTP status where 200 was expected.
    #[error("gateway returned HTTP status {0}")]
    Http(u16),
    /// The gateway rejected the SOAP action (UPnP error code, e.g. 718 conflict).
    #[error("gateway rejected the mapping (UPnP error {0})")]
    Soap(u16),
    /// A response was missing an expected field.
    #[error("malformed gateway response")]
    Malformed,
    /// A gateway response exceeded the fixed memory budget.
    #[error("gateway HTTP response exceeds the {MAX_HTTP_RESPONSE}-byte limit")]
    ResponseTooLarge,
    /// The device description tried to send SOAP requests to another origin.
    #[error("gateway advertised a control URL on a different HTTP origin")]
    UntrustedControlUrl,
}

/// Map an external UDP port to `internal_port` on this host via UPnP, discovering
/// the gateway by SSDP. `description` labels the mapping in the router's UI.
/// Returns the external `ip:port` inbound traffic can reach.
///
/// # Panics
///
/// Does not panic.
pub async fn map_port_upnp(
    internal_port: u16,
    lifetime: Duration,
    description: &str,
) -> Result<Mapping, UpnpError> {
    let location = discover_location().await?;
    map_via_location(&location, internal_port, lifetime, description).await
}

/// Discover a gateway and return the LOCATION URL of its device description.
pub(crate) async fn discover_location() -> Result<String, UpnpError> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let msearch = build_msearch(IGD_DEVICE);
    sock.send_to(msearch.as_bytes(), (SSDP_ADDR, SSDP_PORT))
        .await?;

    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + DISCOVER_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                if let Some(loc) = parse_location(&text) {
                    if location_is_trustworthy(loc, from.ip()) {
                        return Ok(loc.to_string());
                    }
                }
                // Spoofed, non-http, or headerless — keep listening to the deadline.
            }
            Ok(Err(e)) => return Err(UpnpError::Io(e)),
            Err(_) => return Err(UpnpError::NoGateway),
        }
    }
}

/// Given a device-description URL, add the mapping and return the external address.
pub(crate) async fn map_via_location(
    location: &str,
    internal_port: u16,
    lifetime: Duration,
    description: &str,
) -> Result<Mapping, UpnpError> {
    let (status, xml) = http_request("GET", location, &[], "").await?;
    if status != 200 {
        return Err(UpnpError::Http(status));
    }
    let service = parse_igd_service(&xml).ok_or(UpnpError::BadDescription)?;
    let control_url =
        resolve_url(location, &service.control_url).ok_or(UpnpError::BadDescription)?;
    if !same_http_origin(location, &control_url) {
        return Err(UpnpError::UntrustedControlUrl);
    }

    // Our LAN address on the interface toward the gateway — the internal client
    // the mapping forwards to.
    let (host, _, _) = parse_url(&control_url).ok_or(UpnpError::Malformed)?;
    let internal_client = local_ip_towards(&host).await?;

    // IGDv1 lease is a u32 of seconds. Clamp to at least 1s: a gateway reads 0 as
    // "until reboot", so a sub-second Duration truncating to 0 would silently
    // request a permanent mapping. (Mirrors the PCP path's lifetime clamp.)
    let lease = lifetime.as_secs().clamp(1, u32::MAX as u64) as u32;
    let add = soap_add_port_mapping(
        &service.service_type,
        internal_port,
        internal_port,
        internal_client,
        lease,
        description,
    );
    soap_call(&control_url, &service.service_type, "AddPortMapping", &add).await?;

    let get = soap_body(&service.service_type, "GetExternalIPAddress", "");
    let resp = soap_call(
        &control_url,
        &service.service_type,
        "GetExternalIPAddress",
        &get,
    )
    .await?;
    let external_ip: IpAddr = extract_tag(&resp, "NewExternalIPAddress")
        .and_then(|s| s.parse().ok())
        .ok_or(UpnpError::Malformed)?;

    Ok(Mapping {
        external: SocketAddr::new(external_ip, internal_port),
        lifetime: Duration::from_secs(lease as u64),
    })
}

/// The interface address this host uses to reach `host` (via a route lookup on a
/// connected UDP socket; no packet is sent).
async fn local_ip_towards(host: &str) -> Result<IpAddr, UpnpError> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    sock.connect((host, 9)).await?; // port 9 = discard; connect only resolves the route
    Ok(sock.local_addr()?.ip())
}

/// A WAN connection service found in a device description.
struct Service {
    service_type: String,
    control_url: String,
}

/// The SSDP `M-SEARCH` datagram searching for device type `st`.
fn build_msearch(st: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: {st}\r\n\r\n"
    )
}

/// The `LOCATION` header value from an SSDP response (case-insensitive), if any.
fn parse_location(response: &str) -> Option<&str> {
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case("location")
            .then(|| value.trim())
    })
}

/// Whether a discovered LOCATION is safe to fetch. Any host on the LAN can reply
/// to our multicast search, so we reject a LOCATION we can't fetch (non-`http`,
/// which our client doesn't speak) and, when its host is an IP literal, one that
/// doesn't match the responder's address — so a rogue peer can't redirect us to
/// an arbitrary host (an SSRF-style pivot).
fn location_is_trustworthy(location: &str, responder: IpAddr) -> bool {
    let Some((host, _, _)) = parse_url(location) else {
        return false; // not http:// — the HTTP client can't fetch it
    };
    match host.parse::<IpAddr>() {
        Ok(ip) => ip == responder, // IP-literal LOCATION must come from that IP
        Err(_) => true,            // a hostname can't be cheaply verified — allow
    }
}

/// Find the first WAN connection service (and its control URL) in a device
/// description, preferring `WANIPConnection` over `WANPPPConnection`.
fn parse_igd_service(xml: &str) -> Option<Service> {
    for wanted in WAN_SERVICES {
        for block in xml.split("<service>").skip(1) {
            let block = block.split("</service>").next().unwrap_or(block);
            if extract_tag(block, "serviceType") == Some(wanted) {
                if let Some(control) = extract_tag(block, "controlURL") {
                    return Some(Service {
                        service_type: wanted.to_string(),
                        control_url: control.to_string(),
                    });
                }
            }
        }
    }
    None
}

/// The text between `<tag>` and `</tag>` (unprefixed), trimmed.
fn extract_tag<'a>(s: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = s.find(&open)? + open.len();
    let end = s[start..].find(&close)? + start;
    Some(s[start..end].trim())
}

/// Split an `http://host[:port]/path` URL into (host, port, path).
pub(crate) fn parse_url(url: &str) -> Option<(String, u16, String)> {
    // The parsed values are interpolated directly into an HTTP request line and
    // Host header, so allow only printable ASCII (0x21..=0x7e): reject raw
    // whitespace/control bytes (including CR/LF request injection), DEL, and
    // non-ASCII (>= 0x80). RFC 3986 URLs are ASCII — non-ASCII must be
    // percent-encoded/punycoded — and letting a high byte through risks a malformed
    // or ambiguously-parsed request (some parsers treat Unicode separators as
    // whitespace/newlines). Userinfo is rejected below; this small client doesn't
    // need it.
    if url.bytes().any(|b| b <= b' ' || b >= 0x7f) {
        return None;
    }
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

/// Whether two supported HTTP URLs name the same origin. A device description is
/// allowed to choose any control path on its gateway, but not redirect our SOAP
/// POST (which opens a firewall mapping) to another host or port.
fn same_http_origin(a: &str, b: &str) -> bool {
    let (Some((a_host, a_port, _)), Some((b_host, b_port, _))) = (parse_url(a), parse_url(b))
    else {
        return false;
    };
    a_port == b_port && a_host.eq_ignore_ascii_case(&b_host)
}

/// Resolve a (possibly relative) control URL against the device-description URL,
/// per RFC 3986: an absolute-path reference replaces the path; a relative one is
/// resolved against the base path's directory. An absolute URL is returned as-is
/// (a non-`http` scheme then fails cleanly downstream in `parse_url`).
fn resolve_url(base: &str, control: &str) -> Option<String> {
    if control.contains("://") {
        return Some(control.to_string());
    }
    let rest = base.strip_prefix("http://")?;
    let (authority, base_path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if control.starts_with('/') {
        Some(format!("http://{authority}{control}"))
    } else {
        // Relative reference: keep the base path up to and including its last '/'.
        let dir = match base_path.rfind('/') {
            Some(i) => &base_path[..=i],
            None => "/",
        };
        Some(format!("http://{authority}{dir}{control}"))
    }
}

/// Escape text destined for an XML element body. `&` first, so already-escaped
/// entities aren't double-escaped.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// A SOAP envelope for `action` on `service_type`, with the given inner argument
/// XML (may be empty).
fn soap_body(service_type: &str, action: &str, args: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{service_type}\">{args}</u:{action}></s:Body>\
         </s:Envelope>"
    )
}

/// The SOAP body for `AddPortMapping` of a UDP port.
fn soap_add_port_mapping(
    service_type: &str,
    external_port: u16,
    internal_port: u16,
    internal_client: IpAddr,
    lease: u32,
    description: &str,
) -> String {
    let args = format!(
        "<NewRemoteHost></NewRemoteHost>\
         <NewExternalPort>{external_port}</NewExternalPort>\
         <NewProtocol>UDP</NewProtocol>\
         <NewInternalPort>{internal_port}</NewInternalPort>\
         <NewInternalClient>{internal_client}</NewInternalClient>\
         <NewEnabled>1</NewEnabled>\
         <NewPortMappingDescription>{}</NewPortMappingDescription>\
         <NewLeaseDuration>{lease}</NewLeaseDuration>",
        xml_escape(description)
    );
    soap_body(service_type, "AddPortMapping", &args)
}

/// POST a SOAP `action` to `control_url`; return the response body on HTTP 200,
/// else map a fault's `errorCode` to [`UpnpError::Soap`] (or the status).
async fn soap_call(
    control_url: &str,
    service_type: &str,
    action: &str,
    body: &str,
) -> Result<String, UpnpError> {
    let headers = [
        (
            "Content-Type".to_string(),
            "text/xml; charset=\"utf-8\"".to_string(),
        ),
        (
            "SOAPAction".to_string(),
            format!("\"{service_type}#{action}\""),
        ),
    ];
    let (status, resp) = http_request("POST", control_url, &headers, body).await?;
    if status == 200 {
        Ok(resp)
    } else {
        // A UPnP fault carries <errorCode> inside the SOAP fault detail.
        match extract_tag(&resp, "errorCode").and_then(|c| c.parse().ok()) {
            Some(code) => Err(UpnpError::Soap(code)),
            None => Err(UpnpError::Http(status)),
        }
    }
}

/// A minimal HTTP/1.1 request over TCP: `Connection: close`, read the response to
/// EOF within [`MAX_HTTP_RESPONSE`], then split off the body. Returns (status, body).
async fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> Result<(u16, String), UpnpError> {
    let (host, port, path) = parse_url(url).ok_or(UpnpError::Malformed)?;
    let request = || async {
        let mut stream = TcpStream::connect((host.as_str(), port)).await?;
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\
             Connection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);
        stream.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            if raw.len().saturating_add(n) > MAX_HTTP_RESPONSE {
                return Err(UpnpError::ResponseTooLarge);
            }
            raw.extend_from_slice(&chunk[..n]);
        }
        Ok::<_, UpnpError>(raw)
    };
    let raw = timeout(HTTP_TIMEOUT, request()).await.map_err(|_| {
        UpnpError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "gateway HTTP timeout",
        ))
    })??;
    let text = String::from_utf8_lossy(&raw);
    let status = parse_status(&text).ok_or(UpnpError::Malformed)?;
    let resp_body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, resp_body))
}

/// The status code from an HTTP status line (`HTTP/1.1 200 OK`).
fn parse_status(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSDP_RESPONSE: &str = "HTTP/1.1 200 OK\r\n\
        CACHE-CONTROL: max-age=120\r\n\
        LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\
        ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";

    const DEVICE_XML: &str = r#"<?xml version="1.0"?>
        <root><device><serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
            <controlURL>/ctl/CommonIfCfg</controlURL>
          </service>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
            <controlURL>/ctl/IPConn</controlURL>
          </service>
        </serviceList></device></root>"#;

    #[test]
    fn msearch_targets_the_igd() {
        let m = build_msearch(IGD_DEVICE);
        assert!(m.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(m.contains("MAN: \"ssdp:discover\""));
        assert!(m.contains(&format!("ST: {IGD_DEVICE}")));
        assert!(m.ends_with("\r\n\r\n"));
        // No header line may begin with whitespace: a folded line (obs-fold) can
        // make gateways drop the request. (The `\`-newline continuations strip
        // the source indentation, so this holds — this guards that.)
        for line in m.split("\r\n") {
            assert!(
                !line.starts_with([' ', '\t']),
                "folded header line: {line:?}"
            );
        }
    }

    #[test]
    fn parses_the_ssdp_location() {
        assert_eq!(
            parse_location(SSDP_RESPONSE),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
        assert_eq!(parse_location("HTTP/1.1 200 OK\r\nST: foo\r\n\r\n"), None);
    }

    #[test]
    fn finds_the_wan_connection_control_url() {
        let s = parse_igd_service(DEVICE_XML).expect("a WAN service");
        assert_eq!(
            s.service_type,
            "urn:schemas-upnp-org:service:WANIPConnection:1"
        );
        assert_eq!(s.control_url, "/ctl/IPConn");
        assert!(parse_igd_service("<root></root>").is_none());
    }

    #[test]
    fn resolves_control_urls() {
        let base = "http://192.168.1.1:5000/rootDesc.xml";
        // Absolute-path reference replaces the whole path.
        assert_eq!(
            resolve_url(base, "/ctl/IPConn").as_deref(),
            Some("http://192.168.1.1:5000/ctl/IPConn")
        );
        // Absolute URL is passed through unchanged.
        assert_eq!(
            resolve_url(base, "http://192.168.1.1:5000/abs").as_deref(),
            Some("http://192.168.1.1:5000/abs")
        );
        // Relative reference resolves against the base path's directory.
        assert_eq!(
            resolve_url("http://gw/foo/rootDesc.xml", "ctl/IPConn").as_deref(),
            Some("http://gw/foo/ctl/IPConn")
        );
        assert_eq!(
            resolve_url("http://gw/rootDesc.xml", "ctl/IPConn").as_deref(),
            Some("http://gw/ctl/IPConn")
        );
    }

    #[test]
    fn control_url_must_stay_on_the_description_origin() {
        let base = "http://192.168.1.1:5000/rootDesc.xml";
        assert!(same_http_origin(base, "http://192.168.1.1:5000/ctl/IPConn"));
        assert!(!same_http_origin(
            base,
            "http://192.168.1.2:5000/ctl/IPConn"
        ));
        assert!(!same_http_origin(
            base,
            "http://192.168.1.1:5001/ctl/IPConn"
        ));
    }

    #[test]
    fn ssdp_location_is_validated_against_the_responder() {
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        // IP-literal LOCATION that matches the sender — trusted.
        assert!(location_is_trustworthy(
            "http://192.168.1.1:5000/rootDesc.xml",
            gw
        ));
        // IP-literal LOCATION from a different host — a redirect attempt, rejected.
        assert!(!location_is_trustworthy("http://10.0.0.9/evil.xml", gw));
        // Non-http scheme we can't fetch — rejected.
        assert!(!location_is_trustworthy(
            "https://192.168.1.1/rootDesc.xml",
            gw
        ));
        // Hostname LOCATION can't be cheaply verified — allowed.
        assert!(location_is_trustworthy("http://gateway.local/desc.xml", gw));
    }

    #[test]
    fn description_is_xml_escaped_in_the_soap_body() {
        let body = soap_add_port_mapping(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            40000,
            40000,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            3600,
            r#"a & b <x> "q""#,
        );
        assert!(body.contains("a &amp; b &lt;x&gt; &quot;q&quot;"));
        // The raw, unescaped form must not leak into the request.
        assert!(!body.contains("a & b <x>"));
    }

    #[test]
    fn parses_urls() {
        assert_eq!(
            parse_url("http://192.168.1.1:5000/ctl/IPConn"),
            Some(("192.168.1.1".to_string(), 5000, "/ctl/IPConn".to_string()))
        );
        assert_eq!(
            parse_url("http://host/x"),
            Some(("host".to_string(), 80, "/x".to_string()))
        );
        assert_eq!(parse_url("ftp://nope"), None);
        assert_eq!(parse_url("http://host/path\r\nX-Evil: yes"), None);
        assert_eq!(parse_url("http://user@host/path"), None);
        assert_eq!(parse_url("http:///path"), None);
        // Non-ASCII must be percent-encoded/punycoded, not passed through: a raw
        // high byte or a Unicode separator (here U+2028 LINE SEPARATOR) is rejected.
        assert_eq!(
            parse_url("http://xn--hst-nope/path"),
            Some(("xn--hst-nope".to_string(), 80, "/path".to_string()))
        );
        assert_eq!(parse_url("http://höst/path"), None);
        assert_eq!(parse_url("http://host/a\u{2028}b"), None);
    }

    #[test]
    fn extracts_the_external_ip_and_soap_faults() {
        let ok = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>\
                  <NewExternalIPAddress>203.0.113.42</NewExternalIPAddress>\
                  </u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(
            extract_tag(ok, "NewExternalIPAddress"),
            Some("203.0.113.42")
        );

        let fault = "<s:Envelope><s:Body><s:Fault><detail><UPnPError>\
                     <errorCode>718</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert_eq!(extract_tag(fault, "errorCode"), Some("718"));
    }

    #[test]
    fn parses_http_status() {
        assert_eq!(parse_status("HTTP/1.1 200 OK\r\n\r\n"), Some(200));
        assert_eq!(
            parse_status("HTTP/1.1 500 Internal Server Error\r\n"),
            Some(500)
        );
        assert_eq!(parse_status("garbage"), None);
    }

    /// A tiny fake IGD over loopback TCP: serves the device description, then
    /// answers AddPortMapping and GetExternalIPAddress. Handles one request per
    /// connection (the client uses `Connection: close`).
    async fn fake_igd(external_ip: &str) -> SocketAddr {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let external_ip = external_ip.to_string();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                // Read the request (headers + any Content-Length body).
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
                    // AddPortMapping success — an empty response body.
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
    async fn maps_a_port_against_a_fake_igd() {
        let igd = fake_igd("203.0.113.42").await;
        let location = format!("http://{igd}/rootDesc.xml");
        let mapping = map_via_location(&location, 40000, Duration::from_secs(3600), "warren")
            .await
            .expect("mapping should succeed");
        assert_eq!(
            mapping.external,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)), 40000)
        );
        assert_eq!(mapping.lifetime, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn rejects_an_oversized_gateway_response() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = sock.read(&mut request).await;
            let response = vec![b'x'; MAX_HTTP_RESPONSE + 1];
            let _ = sock.write_all(&response).await;
        });

        let url = format!("http://{addr}/too-large");
        assert!(matches!(
            http_request("GET", &url, &[], "").await,
            Err(UpnpError::ResponseTooLarge)
        ));
    }
}
