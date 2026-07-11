//! Small encoding + time helpers shared across the substrate.

use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock unix seconds. The substrate runs in a real application, not the
/// sans-IO core, so using the real clock here is fine.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Parse lowercase/uppercase hex into bytes; `None` on any non-hex or odd length.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Parse a 32-byte hash from hex; `None` unless it's exactly 32 bytes.
pub fn hash_from_hex(s: &str) -> Option<[u8; 32]> {
    bytes_from_hex(s)
}

/// Parse exactly `N` bytes from hex; `None` on any non-hex or wrong length.
pub fn bytes_from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    from_hex(s)?.try_into().ok()
}
