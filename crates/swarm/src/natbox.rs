//! A packet-level NAT model: mapping + filtering for one endpoint.
//!
//! A [`NatBox`] sits in front of one host's UDP sockets and models the two
//! behaviors that decide whether a hole punch works:
//!
//! - **Mapping** — the external port assigned to an outbound flow.
//!   `Consistent`/`Open` use one stable port per local socket (endpoint-
//!   independent); `Random` (symmetric) allocates a fresh port per destination.
//! - **Filtering** — which inbound packets are admitted. `Consistent`/`Random`
//!   use address-and-port-dependent filtering (RFC 4787): a packet is admitted
//!   only from the exact IP:port the owning socket has already sent to. `Open`
//!   admits anything.
//!
//! Driving real packets through two `NatBox`es reproduces hole-punch outcomes
//! from first principles — including the birthday collision — rather than
//! asserting them, which is why the packet-level punch cross-checks the
//! probabilistic model in [`crate::punch`].

use crate::nat::Firewall;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

/// Handle for a local UDP socket behind a [`NatBox`].
pub type SocketId = u64;

/// Models the NAT in front of one host.
#[derive(Debug)]
pub struct NatBox {
    kind: Firewall,
    host: IpAddr,
    port_min: u16,
    port_max: u16,
    next_port: u16,
    next_socket: SocketId,
    /// Endpoint-independent mapping: stable external port per socket.
    socket_port: HashMap<SocketId, u16>,
    /// Endpoint-dependent (symmetric) mapping: external port per (socket, dest).
    per_dest_port: HashMap<(SocketId, SocketAddr), u16>,
    /// Which socket owns each allocated external port.
    port_owner: HashMap<u16, SocketId>,
    /// Address-and-port-dependent filter: exact IP:port sources each external
    /// port will accept.
    port_allow: HashMap<u16, HashSet<SocketAddr>>,
}

impl NatBox {
    /// Create a NAT of the given kind fronting `host`, allocating external ports
    /// across the standard punch range.
    pub fn new(kind: Firewall, host: IpAddr) -> Self {
        Self::with_range(kind, host, 1024, 65535)
    }

    /// Create a NAT with an explicit external-port range.
    ///
    /// Panics if `port_min > port_max`.
    pub fn with_range(kind: Firewall, host: IpAddr, port_min: u16, port_max: u16) -> Self {
        assert!(
            port_min <= port_max,
            "invalid external port range: {port_min} > {port_max}"
        );
        Self {
            kind,
            host,
            port_min,
            port_max,
            next_port: port_min,
            next_socket: 0,
            socket_port: HashMap::new(),
            per_dest_port: HashMap::new(),
            port_owner: HashMap::new(),
            port_allow: HashMap::new(),
        }
    }

    /// The public host this NAT presents.
    pub fn host(&self) -> IpAddr {
        self.host
    }

    /// Open a new local socket.
    pub fn open_socket(&mut self) -> SocketId {
        let id = self.next_socket;
        self.next_socket += 1;
        id
    }

    fn alloc_port(&mut self) -> u16 {
        // Bound the scan to the range size so an exhausted range fails fast
        // instead of spinning forever.
        let span = (self.port_max - self.port_min) as usize + 1;
        for _ in 0..span {
            let p = self.next_port;
            self.next_port = if self.next_port >= self.port_max {
                self.port_min
            } else {
                self.next_port + 1
            };
            if !self.port_owner.contains_key(&p) {
                return p;
            }
        }
        panic!(
            "NAT external port range {}..={} exhausted",
            self.port_min, self.port_max
        );
    }

    /// Send from `socket` to `dest`; returns the external source address the
    /// destination observes, and records the mapping and (for filtered NATs) an
    /// allowance for return traffic from `dest`.
    pub fn send(&mut self, socket: SocketId, dest: SocketAddr) -> SocketAddr {
        let port = match self.kind {
            Firewall::Open | Firewall::Consistent => match self.socket_port.get(&socket) {
                Some(&p) => p,
                None => {
                    let p = self.alloc_port();
                    self.socket_port.insert(socket, p);
                    p
                }
            },
            Firewall::Random => match self.per_dest_port.get(&(socket, dest)) {
                Some(&p) => p,
                None => {
                    let p = self.alloc_port();
                    self.per_dest_port.insert((socket, dest), p);
                    p
                }
            },
        };
        self.port_owner.insert(port, socket);
        // Open admits any source, so recv never consults the filter — don't
        // grow it for nothing.
        if self.kind != Firewall::Open {
            self.port_allow.entry(port).or_default().insert(dest);
        }
        SocketAddr::new(self.host, port)
    }

    /// Deliver an inbound packet addressed to external `port` from `from`.
    /// Returns the receiving socket, or `None` if no mapping exists or the
    /// filter rejects the source.
    pub fn recv(&self, port: u16, from: SocketAddr) -> Option<SocketId> {
        let owner = *self.port_owner.get(&port)?;
        match self.kind {
            // Publicly reachable: any source is admitted to a bound port.
            Firewall::Open => Some(owner),
            // Address-and-port-dependent: only from an exact IP:port sent to.
            Firewall::Consistent | Firewall::Random => {
                if self.port_allow.get(&port)?.contains(&from) {
                    Some(owner)
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn host(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, d))
    }

    fn dest(d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(host(d), port)
    }

    #[test]
    fn consistent_mapping_is_endpoint_independent() {
        let mut nat = NatBox::new(Firewall::Consistent, host(1));
        let s = nat.open_socket();
        let a = nat.send(s, dest(2, 100));
        let b = nat.send(s, dest(3, 200));
        assert_eq!(
            a.port(),
            b.port(),
            "same socket must map to one stable port"
        );
    }

    #[test]
    fn random_mapping_is_per_destination() {
        let mut nat = NatBox::new(Firewall::Random, host(1));
        let s = nat.open_socket();
        let a = nat.send(s, dest(2, 100));
        let b = nat.send(s, dest(3, 200));
        assert_ne!(a.port(), b.port(), "symmetric NAT must vary port per dest");
    }

    #[test]
    fn address_restricted_filter_blocks_unsolicited() {
        let mut nat = NatBox::new(Firewall::Consistent, host(1));
        let s = nat.open_socket();
        let ext = nat.send(s, dest(2, 100));
        // Reply from the destination we contacted is admitted...
        assert_eq!(nat.recv(ext.port(), dest(2, 100)), Some(s));
        // ...but an unsolicited source is dropped.
        assert_eq!(nat.recv(ext.port(), dest(9, 999)), None);
    }

    #[test]
    fn open_admits_any_source() {
        let mut nat = NatBox::new(Firewall::Open, host(1));
        let s = nat.open_socket();
        let ext = nat.send(s, dest(2, 100));
        assert_eq!(nat.recv(ext.port(), dest(9, 999)), Some(s));
    }

    #[test]
    fn recv_on_unmapped_port_is_none() {
        let nat = NatBox::new(Firewall::Open, host(1));
        assert_eq!(nat.recv(4242, dest(2, 100)), None);
    }
}
