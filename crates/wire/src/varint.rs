use crate::error::{Result, WireError};

/// Maximum number of bytes an LEB128-encoded `u64` can occupy.
pub const MAX_VARINT_LEN: usize = 10;

/// Append `value` to `out` as an unsigned LEB128 varint.
pub fn encode_uint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Decode an unsigned LEB128 varint from the front of `buf`.
///
/// Returns the decoded value and the number of bytes consumed.
pub fn decode_uint(buf: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;

    for (i, &byte) in buf.iter().enumerate() {
        let low = u64::from(byte & 0x7f);

        // At shift 63 only the single top bit is available, so any payload
        // beyond bit 0 — or any continuation past 10 bytes — overflows u64.
        if shift >= 64 || (shift == 63 && low > 1) {
            return Err(WireError::Overflow);
        }

        result |= low << shift;

        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }

    Err(WireError::UnexpectedEof {
        needed: 1,
        remaining: 0,
    })
}

/// Number of bytes `value` will occupy once LEB128-encoded.
pub fn encoded_len(value: u64) -> usize {
    let mut n = 1;
    let mut v = value >> 7;
    while v != 0 {
        n += 1;
        v >>= 7;
    }
    n
}
