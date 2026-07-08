//! NAT self-classification.
//!
//! A node cannot punch a hole until it knows what kind of NAT sits in front of
//! it. Following HyperDHT, we learn this by *sampling*: ping several DHT nodes
//! and observe the source address each reports seeing. The pattern of observed
//! addresses classifies the firewall:
//!
//! - **Open** — not firewalled; reachable on a stable public address.
//! - **Consistent** — firewalled but the external port is stable across
//!   destinations (endpoint-independent mapping), so a peer can predict it.
//! - **Random** — symmetric NAT; a fresh external port per destination, so the
//!   port cannot be predicted. This is the hard case the birthday strategy
//!   exists for.
//!
//! Classification is pure: feed it observations and a reachability flag, get a
//! verdict. That makes it directly unit-testable without any network.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Minimum number of samples before a verdict can be reached.
pub const MIN_SAMPLES: usize = 3;

/// The classified firewall type in front of a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Firewall {
    /// Publicly reachable; unsolicited inbound works.
    Open,
    /// Firewalled, but external port is stable and predictable.
    Consistent,
    /// Firewalled with an unpredictable (per-destination) external port.
    Random,
}

/// Accumulates observed external addresses to classify the local firewall.
///
/// Each observation is the source address a distinct remote node reported
/// seeing when this node pinged it *from the same local socket*.
#[derive(Default, Debug)]
pub struct NatSampler {
    observations: Vec<SocketAddr>,
}

impl NatSampler {
    /// Create an empty sampler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observed external address.
    pub fn add(&mut self, observed: SocketAddr) {
        self.observations.push(observed);
    }

    /// Number of observations collected.
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Whether no observations have been collected.
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// The most-observed external host, if any.
    pub fn host(&self) -> Option<IpAddr> {
        majority(self.observations.iter().map(|a| a.ip()))
    }

    /// Classify the firewall.
    ///
    /// `reachable` is the result of a firewall probe (did an unsolicited
    /// inbound packet arrive on our server socket?). Returns `None` while fewer
    /// than [`MIN_SAMPLES`] observations exist.
    ///
    /// The port rule mirrors HyperDHT: a single external port seen at least
    /// three times is a stable mapping (Consistent, or Open if reachable);
    /// otherwise the port is varying and the NAT is Random.
    pub fn classify(&self, reachable: bool) -> Option<Firewall> {
        if self.observations.len() < MIN_SAMPLES {
            return None;
        }

        // Count occurrences of each full (host, port) observation.
        let mut counts: HashMap<SocketAddr, usize> = HashMap::new();
        for &addr in &self.observations {
            *counts.entry(addr).or_default() += 1;
        }
        let top = counts.values().copied().max().unwrap_or(0);

        if top >= 3 {
            Some(if reachable {
                Firewall::Open
            } else {
                Firewall::Consistent
            })
        } else {
            Some(Firewall::Random)
        }
    }
}

fn majority<I, T>(items: I) -> Option<T>
where
    I: IntoIterator<Item = T>,
    T: Eq + std::hash::Hash + Clone,
{
    let mut counts: HashMap<T, usize> = HashMap::new();
    for item in items {
        *counts.entry(item).or_default() += 1;
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(k, _)| k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(host: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(host), port))
    }

    #[test]
    fn too_few_samples_is_undecided() {
        let mut s = NatSampler::new();
        s.add(addr([1, 2, 3, 4], 1000));
        s.add(addr([1, 2, 3, 4], 1000));
        assert_eq!(s.classify(false), None);
    }

    #[test]
    fn stable_port_while_reachable_is_open() {
        let mut s = NatSampler::new();
        for _ in 0..3 {
            s.add(addr([1, 2, 3, 4], 1000));
        }
        assert_eq!(s.classify(true), Some(Firewall::Open));
    }

    #[test]
    fn stable_port_while_firewalled_is_consistent() {
        let mut s = NatSampler::new();
        for _ in 0..4 {
            s.add(addr([1, 2, 3, 4], 1000));
        }
        assert_eq!(s.classify(false), Some(Firewall::Consistent));
    }

    #[test]
    fn varying_ports_is_random() {
        let mut s = NatSampler::new();
        s.add(addr([1, 2, 3, 4], 1000));
        s.add(addr([1, 2, 3, 4], 2000));
        s.add(addr([1, 2, 3, 4], 3000));
        s.add(addr([1, 2, 3, 4], 4000));
        assert_eq!(s.classify(false), Some(Firewall::Random));
    }

    #[test]
    fn two_of_four_matching_is_not_enough_for_consistent() {
        // Only a majority-but-under-3 repeat is still treated as random,
        // matching the conservative HyperDHT threshold.
        let mut s = NatSampler::new();
        s.add(addr([1, 2, 3, 4], 1000));
        s.add(addr([1, 2, 3, 4], 1000));
        s.add(addr([1, 2, 3, 4], 2000));
        s.add(addr([1, 2, 3, 4], 3000));
        assert_eq!(s.classify(false), Some(Firewall::Random));
    }

    #[test]
    fn reports_majority_host() {
        let mut s = NatSampler::new();
        s.add(addr([9, 9, 9, 9], 1));
        s.add(addr([9, 9, 9, 9], 2));
        s.add(addr([1, 1, 1, 1], 3));
        assert_eq!(s.host(), Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))));
    }
}
