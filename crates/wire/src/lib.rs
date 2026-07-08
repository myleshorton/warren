//! Wire codec: the byte-level (de)serialization every protocol layer shares.
//!
//! This crate is deliberately tiny and pure — no I/O, no allocation beyond the
//! output buffer — so it can be exhaustively property-tested. Everything above
//! it (DHT RPC, replication messages, log/blob headers) encodes through
//! [`Encoder`] and decodes through [`Decoder`].
//!
//! Integers use unsigned LEB128 varints; byte slices are length-delimited by a
//! varint prefix; fixed-width integers are little-endian.
//!
//! ```
//! use wire::{Encoder, Decoder};
//!
//! let mut enc = Encoder::new();
//! enc.uint(300);
//! enc.bytes(b"hello");
//! let buf = enc.into_vec();
//!
//! let mut dec = Decoder::new(&buf);
//! assert_eq!(dec.uint().unwrap(), 300);
//! assert_eq!(dec.bytes().unwrap(), b"hello");
//! dec.finish().unwrap();
//! ```

mod error;
mod varint;

pub use error::{Result, WireError};
pub use varint::{decode_uint, encode_uint, encoded_len, MAX_VARINT_LEN};

/// Growable buffer that appends values in wire format.
///
/// Encoding is infallible — methods return `&mut Self` so calls can chain.
#[derive(Debug, Default, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Create an empty encoder.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create an encoder with room for `cap` bytes reserved up front.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Number of bytes written so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrow the written bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Consume the encoder and return the written bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Append an unsigned LEB128 varint.
    pub fn uint(&mut self, value: u64) -> &mut Self {
        encode_uint(&mut self.buf, value);
        self
    }

    /// Append a single byte.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Append a little-endian `u16`.
    pub fn u16_le(&mut self, value: u16) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append a little-endian `u32`.
    pub fn u32_le(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append a little-endian `u64`.
    pub fn u64_le(&mut self, value: u64) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append raw bytes with no length prefix.
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a length-delimited byte slice (varint length, then the bytes).
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.uint(bytes.len() as u64);
        self.buf.extend_from_slice(bytes);
        self
    }
}

/// Cursor that reads values from a byte buffer in wire format.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Wrap a buffer for reading.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Byte offset of the cursor.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether the cursor has reached the end.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(WireError::UnexpectedEof {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Read an unsigned LEB128 varint.
    pub fn uint(&mut self) -> Result<u64> {
        let (value, used) = decode_uint(&self.buf[self.pos..])?;
        self.pos += used;
        Ok(value)
    }

    /// Read a single byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `u16`.
    pub fn u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array::<2>()?))
    }

    /// Read a little-endian `u32`.
    pub fn u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    /// Read a little-endian `u64`.
    pub fn u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }

    /// Read exactly `n` raw bytes.
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    /// Read a fixed-size array of `N` bytes.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    /// Read a length-delimited byte slice written by [`Encoder::bytes`].
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.uint()?;
        // Reject a length that cannot possibly be satisfied before allocating
        // or slicing, so a corrupt prefix can't drive a huge read.
        if len > self.remaining() as u64 {
            return Err(WireError::LengthTooLarge {
                len,
                remaining: self.remaining(),
            });
        }
        self.take(len as usize)
    }

    /// Assert the buffer was fully consumed.
    pub fn finish(self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(WireError::TrailingBytes(self.remaining()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_boundaries_roundtrip() {
        // Values that sit exactly on LEB128 byte-length boundaries.
        for v in [
            0u64,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            encode_uint(&mut out, v);
            assert_eq!(out.len(), encoded_len(v), "encoded_len wrong for {v}");
            let (got, used) = decode_uint(&out).unwrap();
            assert_eq!(got, v);
            assert_eq!(used, out.len());
        }
    }

    #[test]
    fn u64_max_uses_ten_bytes() {
        let mut out = Vec::new();
        encode_uint(&mut out, u64::MAX);
        assert_eq!(out.len(), MAX_VARINT_LEN);
    }

    #[test]
    fn varint_overflow_is_rejected() {
        // Eleven continuation bytes can never fit in u64.
        let overflowing = [0xffu8; 11];
        assert_eq!(decode_uint(&overflowing), Err(WireError::Overflow));
    }

    #[test]
    fn truncated_varint_is_eof() {
        // A lone continuation byte with no terminator.
        assert!(matches!(
            decode_uint(&[0x80]),
            Err(WireError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn mixed_roundtrip() {
        let mut enc = Encoder::new();
        enc.uint(1)
            .u8(2)
            .u16_le(3)
            .u32_le(4)
            .u64_le(5)
            .bytes(b"payload")
            .raw(&[9, 9]);
        let buf = enc.into_vec();

        let mut dec = Decoder::new(&buf);
        assert_eq!(dec.uint().unwrap(), 1);
        assert_eq!(dec.u8().unwrap(), 2);
        assert_eq!(dec.u16_le().unwrap(), 3);
        assert_eq!(dec.u32_le().unwrap(), 4);
        assert_eq!(dec.u64_le().unwrap(), 5);
        assert_eq!(dec.bytes().unwrap(), b"payload");
        assert_eq!(dec.raw(2).unwrap(), &[9, 9]);
        dec.finish().unwrap();
    }

    #[test]
    fn finish_rejects_trailing_bytes() {
        let mut dec = Decoder::new(&[1, 2, 3]);
        dec.u8().unwrap();
        assert_eq!(dec.finish(), Err(WireError::TrailingBytes(2)));
    }

    #[test]
    fn bytes_rejects_oversized_length_prefix() {
        // Varint length 200 with only a few bytes behind it.
        let mut buf = Vec::new();
        encode_uint(&mut buf, 200);
        buf.extend_from_slice(&[0; 3]);
        let mut dec = Decoder::new(&buf);
        assert!(matches!(
            dec.bytes(),
            Err(WireError::LengthTooLarge { len: 200, .. })
        ));
    }

    #[test]
    fn reading_past_end_is_eof() {
        let mut dec = Decoder::new(&[1]);
        assert_eq!(dec.u8().unwrap(), 1);
        assert!(matches!(
            dec.u8(),
            Err(WireError::UnexpectedEof {
                needed: 1,
                remaining: 0
            })
        ));
    }
}
