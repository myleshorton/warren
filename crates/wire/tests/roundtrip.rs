//! Property tests: invariants that must hold for every input, checked against
//! thousands of randomized cases (scale with `PROPTEST_CASES`, see `make test-deep`).

use proptest::prelude::*;
use wire::{decode_uint, encode_uint, encoded_len, Decoder, Encoder};

proptest! {
    /// Any u64 survives an encode -> decode round trip unchanged, and reports
    /// the exact number of bytes it occupied.
    #[test]
    fn uint_roundtrips(v: u64) {
        let mut out = Vec::new();
        encode_uint(&mut out, v);
        prop_assert_eq!(out.len(), encoded_len(v));
        let (got, used) = decode_uint(&out).unwrap();
        prop_assert_eq!(got, v);
        prop_assert_eq!(used, out.len());
    }

    /// A varint decode never reads beyond its own terminator: appending garbage
    /// after a valid varint changes neither the value nor the byte count.
    #[test]
    fn uint_ignores_trailing_garbage(v: u64, garbage: Vec<u8>) {
        let mut out = Vec::new();
        encode_uint(&mut out, v);
        let boundary = out.len();
        out.extend_from_slice(&garbage);
        let (got, used) = decode_uint(&out).unwrap();
        prop_assert_eq!(got, v);
        prop_assert_eq!(used, boundary);
    }

    /// A length-delimited byte slice of any content round-trips exactly.
    #[test]
    fn bytes_roundtrip(payload: Vec<u8>) {
        let mut enc = Encoder::new();
        enc.bytes(&payload);
        let buf = enc.into_vec();

        let mut dec = Decoder::new(&buf);
        prop_assert_eq!(dec.bytes().unwrap(), payload.as_slice());
        prop_assert!(dec.finish().is_ok());
    }

    /// A heterogeneous record round-trips field-for-field regardless of values.
    #[test]
    fn record_roundtrip(a: u64, b: u8, c: u32, key: [u8; 32], payload: Vec<u8>) {
        let mut enc = Encoder::new();
        enc.uint(a).u8(b).u32_le(c).raw(&key).bytes(&payload);
        let buf = enc.into_vec();

        let mut dec = Decoder::new(&buf);
        prop_assert_eq!(dec.uint().unwrap(), a);
        prop_assert_eq!(dec.u8().unwrap(), b);
        prop_assert_eq!(dec.u32_le().unwrap(), c);
        prop_assert_eq!(dec.array::<32>().unwrap(), key);
        prop_assert_eq!(dec.bytes().unwrap(), payload.as_slice());
        prop_assert!(dec.finish().is_ok());
    }

    /// Decoding must never panic on arbitrary/adversarial input — it either
    /// yields a value or a clean error. This is the fuzz-resistance guarantee
    /// the whole wire format leans on.
    #[test]
    fn decode_never_panics_on_arbitrary_input(buf: Vec<u8>) {
        let mut dec = Decoder::new(&buf);
        let _ = dec.uint();
        let _ = dec.bytes();
        let _ = dec.u64_le();
        let _ = dec.array::<32>();
    }

    /// Truncating a valid encoding at any point yields an error, never a wrong
    /// value or a panic.
    #[test]
    fn truncation_is_always_an_error(payload: Vec<u8>, cut in 0usize..64) {
        prop_assume!(!payload.is_empty());
        let mut enc = Encoder::new();
        enc.bytes(&payload);
        let buf = enc.into_vec();
        let cut = cut.min(buf.len().saturating_sub(1));

        let mut dec = Decoder::new(&buf[..cut]);
        // Either the length prefix is unreadable, or it promises more than the
        // truncated buffer holds — both are clean errors.
        prop_assert!(dec.bytes().is_err());
    }
}
