//! Public routing namespaces, not authentication or geographic admission.

pub(super) const HEADER_LEN: usize = 32;
const MAGIC: &[u8; 4] = b"WRO1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum OverlayId {
    #[default]
    Global,
    Regional([u8; 28]),
}

impl OverlayId {
    /// Deployment-chosen label; all participants must use exactly the same bytes.
    pub fn regional(label: &str) -> Self {
        let hash = crypto::hash_parts(&[b"warren:regional-overlay:v1", label.as_bytes()]);
        Self::Regional(hash[..28].try_into().expect("fixed overlay identifier"))
    }

    pub(super) fn frame(self, bytes: Vec<u8>) -> Vec<u8> {
        match self {
            Self::Global => bytes,
            Self::Regional(id) => {
                let mut framed = Vec::with_capacity(HEADER_LEN + bytes.len());
                framed.extend_from_slice(MAGIC);
                framed.extend_from_slice(&id);
                framed.extend_from_slice(&bytes);
                framed
            }
        }
    }

    pub(super) fn payload(self, bytes: &[u8]) -> Option<&[u8]> {
        match self {
            Self::Global => (!bytes.starts_with(MAGIC)).then_some(bytes),
            Self::Regional(id) => {
                if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC || bytes[4..HEADER_LEN] != id {
                    None
                } else {
                    Some(&bytes[HEADER_LEN..])
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_reject_each_other_and_truncated_frames() {
        const { assert!(dht_next::protocol::MAX_PACKET + HEADER_LEN + 40 + 8 <= 1280) };
        let iran = OverlayId::regional("ir");
        let other = OverlayId::regional("other");
        let frame = iran.frame(vec![1, 2, 3]);
        assert_eq!(iran.payload(&frame), Some(&[1, 2, 3][..]));
        assert!(other.payload(&frame).is_none());
        assert!(OverlayId::Global.payload(&frame).is_none());
        assert!(iran.payload(&[1, 2, 3]).is_none());
        for end in 0..HEADER_LEN {
            assert!(iran.payload(&frame[..end]).is_none());
        }
        assert_eq!(OverlayId::Global.frame(vec![1, 2]), vec![1, 2]);
    }
}
