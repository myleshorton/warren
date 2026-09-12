//! Versioned, bounded contact hints. Import never installs trusted routing state.
use dht_next::{Contact, NodeId, MAX_CANDIDATES};
use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const HEADER: &[u8; 4] = b"WBS1";
const RECORD: usize = 51;

#[derive(Clone, Debug)]
pub struct BootstrapState {
    contacts: Vec<Contact>,
}
impl BootstrapState {
    pub fn contacts(&self) -> &[Contact] {
        &self.contacts
    }
    pub(super) fn new(contacts: Vec<Contact>) -> Self {
        let mut ids = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        let contacts = contacts
            .into_iter()
            .filter_map(|contact| {
                let ip = match contact.addr.ip() {
                    IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
                    ip => ip,
                };
                let address = SocketAddr::new(ip, contact.addr.port());
                if !usable(address) || ids.contains(&contact.id) || addresses.contains(&address) {
                    return None;
                }
                ids.insert(contact.id);
                addresses.insert(address);
                Some(Contact::new(contact.id, address))
            })
            .take(MAX_CANDIDATES)
            .collect();
        Self { contacts }
    }
    /// Caller chooses storage and atomic-write policy. No private keys, cookies,
    /// provider leases, monotonic timestamps or encryption state are serialized.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(6 + self.contacts.len() * RECORD);
        bytes.extend_from_slice(HEADER);
        bytes.extend_from_slice(&(self.contacts.len() as u16).to_be_bytes());
        for contact in &self.contacts {
            bytes.extend_from_slice(contact.id.as_bytes());
            match contact.addr.ip() {
                IpAddr::V4(ip) => {
                    bytes.push(4);
                    bytes.extend_from_slice(&ip.octets());
                    bytes.extend_from_slice(&[0; 12]);
                }
                IpAddr::V6(ip) => {
                    bytes.push(6);
                    bytes.extend_from_slice(&ip.octets());
                }
            }
            bytes.extend_from_slice(&contact.addr.port().to_be_bytes());
        }
        bytes
    }
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid bootstrap state");
        if bytes.len() < 6 || &bytes[..4] != HEADER {
            return Err(invalid());
        }
        let count = u16::from_be_bytes(bytes[4..6].try_into().unwrap()) as usize;
        if count > MAX_CANDIDATES || bytes.len() != 6 + count * RECORD {
            return Err(invalid());
        }
        let mut contacts = Vec::with_capacity(count);
        let mut ids = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for record in bytes[6..].chunks_exact(RECORD) {
            let id = NodeId::from_bytes(record[..32].try_into().unwrap());
            let ip = match record[32] {
                4 if record[37..49] == [0; 12] => IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&record[33..37]).unwrap(),
                )),
                6 => {
                    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&record[33..49]).unwrap());
                    ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)
                }
                _ => return Err(invalid()),
            };
            let port = u16::from_be_bytes(record[49..51].try_into().unwrap());
            let address = SocketAddr::new(ip, port);
            if !usable(address) || !ids.insert(id) || !addresses.insert(address) {
                return Err(invalid());
            }
            contacts.push(Contact::new(id, address));
        }
        Ok(Self { contacts })
    }
}

fn usable(address: SocketAddr) -> bool {
    let ip = address.ip();
    address.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
        && !matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exported_hints_normalize_and_deduplicate_endpoints() {
        let state = BootstrapState::new(vec![
            Contact::new(NodeId::from_bytes([1; 32]), "192.0.2.1:42".parse().unwrap()),
            Contact::new(
                NodeId::from_bytes([2; 32]),
                "[::ffff:192.0.2.1]:42".parse().unwrap(),
            ),
            Contact::new(NodeId::from_bytes([3; 32]), "[fe80::1]:42".parse().unwrap()),
        ]);
        assert_eq!(state.contacts.len(), 1);
        assert_eq!(
            BootstrapState::decode(&state.encode()).unwrap().contacts(),
            state.contacts()
        );
    }
    #[test]
    fn snapshot_roundtrip_and_strict_framing() {
        let state = BootstrapState::new(vec![
            Contact::new(
                NodeId::from_bytes([1; 32]),
                "192.0.2.1:1234".parse().unwrap(),
            ),
            Contact::new(
                NodeId::from_bytes([2; 32]),
                "[2001:db8::1]:5678".parse().unwrap(),
            ),
        ]);
        let bytes = state.encode();
        assert_eq!(
            BootstrapState::decode(&bytes).unwrap().contacts(),
            state.contacts()
        );
        for len in 0..bytes.len() {
            assert!(BootstrapState::decode(&bytes[..len]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(BootstrapState::decode(&extra).is_err());
        for offset in [0, 38, 43] {
            let mut corrupt = bytes.clone();
            corrupt[offset] = 255;
            assert!(BootstrapState::decode(&corrupt).is_err());
        }
        let mut duplicate = bytes.clone();
        duplicate[6 + RECORD..].copy_from_slice(&bytes[6..6 + RECORD]);
        assert!(BootstrapState::decode(&duplicate).is_err());
        let mut oversized = b"WBS1".to_vec();
        oversized.extend_from_slice(&129u16.to_be_bytes());
        assert!(BootstrapState::decode(&oversized).is_err());
        assert!(BootstrapState::decode(b"WBS1\0\0")
            .unwrap()
            .contacts()
            .is_empty());
    }
}
