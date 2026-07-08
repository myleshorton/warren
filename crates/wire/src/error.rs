use thiserror::Error;

/// Errors produced while decoding a byte buffer.
///
/// Encoding never fails (it grows an in-memory buffer), so all wire errors
/// arise on the decode path and describe exactly why a buffer was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WireError {
    /// The buffer ended before a value could be fully read.
    #[error("unexpected end of buffer: needed {needed} more byte(s), had {remaining}")]
    UnexpectedEof { needed: usize, remaining: usize },

    /// A varint encoded a value that does not fit in the target integer.
    #[error("varint overflows u64")]
    Overflow,

    /// A length prefix claimed more bytes than the buffer could ever hold.
    #[error("length prefix {len} exceeds remaining buffer {remaining}")]
    LengthTooLarge { len: u64, remaining: usize },

    /// `finish` was called but unread bytes remained.
    #[error("{0} trailing byte(s) left after decoding")]
    TrailingBytes(usize),
}

/// Result specialized to [`WireError`].
pub type Result<T> = core::result::Result<T, WireError>;
