//! Node identifiers and the Kademlia XOR distance metric.
//!
//! A [`NodeId`] is an opaque 256-bit identifier. Closeness between two ids is
//! their bitwise XOR interpreted as a big-endian integer — the metric that
//! makes Kademlia routing work: it is symmetric, and for any target there is a
//! unique closest id.

/// Length of a node id, in bytes.
pub const ID_LEN: usize = 32;

/// A 256-bit node identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; ID_LEN]);

impl NodeId {
    /// Construct from raw bytes.
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    /// The XOR distance to another id.
    pub fn distance(&self, other: &NodeId) -> Distance {
        let mut d = [0u8; ID_LEN];
        for (out, (a, b)) in d.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *out = a ^ b;
        }
        Distance(d)
    }
}

impl core::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "NodeId({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// The XOR distance between two [`NodeId`]s.
///
/// Ordered as a big-endian 256-bit integer, so smaller means closer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Distance([u8; ID_LEN]);

impl Distance {
    /// Distance zero — an id's distance to itself.
    pub const ZERO: Distance = Distance([0u8; ID_LEN]);

    /// Number of leading zero bits.
    ///
    /// This is the length of the shared prefix between the two ids, and thus the
    /// Kademlia k-bucket index for the more distant id relative to the closer.
    pub fn leading_zeros(&self) -> u32 {
        let mut n = 0;
        for &byte in &self.0 {
            if byte == 0 {
                n += 8;
            } else {
                n += byte.leading_zeros();
                break;
            }
        }
        n
    }

    /// The raw distance bytes.
    pub fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Distance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Distance(lz={})", self.leading_zeros())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; ID_LEN])
    }

    #[test]
    fn distance_to_self_is_zero() {
        assert_eq!(id(0xab).distance(&id(0xab)), Distance::ZERO);
        assert_eq!(id(0xab).distance(&id(0xab)).leading_zeros(), 256);
    }

    #[test]
    fn distance_is_symmetric() {
        let a = id(0x0f);
        let b = id(0xf0);
        assert_eq!(a.distance(&b), b.distance(&a));
    }

    #[test]
    fn leading_zeros_locates_first_differing_bit() {
        let a = NodeId::from_bytes([0u8; ID_LEN]);
        let mut b = [0u8; ID_LEN];
        // Differ only at bit 0 of byte 1 -> 8 leading zero bits.
        b[1] = 0b1000_0000;
        let d = a.distance(&NodeId::from_bytes(b));
        assert_eq!(d.leading_zeros(), 8);
    }

    #[test]
    fn closer_ids_have_smaller_distance() {
        let target = id(0x00);
        let near = NodeId::from_bytes({
            let mut x = [0u8; ID_LEN];
            x[0] = 0x01;
            x
        });
        let far = id(0xff);
        assert!(target.distance(&near) < target.distance(&far));
    }
}
