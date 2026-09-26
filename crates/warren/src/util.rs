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

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url (RFC 4648 §5).
pub fn to_base64url(bytes: &[u8]) -> String {
    let mut s = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0u32, |word, (i, b)| word | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            s.push(BASE64URL[(word >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    s
}

/// Parse unpadded base64url; `None` on padding, any other alphabet, an
/// impossible length, or nonzero trailing bits, so each byte string has one text form.
pub fn from_base64url(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let value = BASE64URL.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (bits < 6 && acc == 0).then_some(out)
}

/// Parse a 32-byte hash from hex; `None` unless it's exactly 32 bytes.
pub fn hash_from_hex(s: &str) -> Option<[u8; 32]> {
    bytes_from_hex(s)
}

/// Parse exactly `N` bytes from hex; `None` on any non-hex or wrong length.
pub fn bytes_from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    from_hex(s)?.try_into().ok()
}
