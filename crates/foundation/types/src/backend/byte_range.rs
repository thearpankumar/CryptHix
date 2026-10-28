//! Byte ranges for reads.

use crate::backend::BackendError;

/// A range of bytes in a file. Every read is bounded, so a hostile backend cannot make the
/// caller allocate without limit (T-39).
///
/// Implementations must not pre-allocate [`len`](Self::len) bytes: it is an upper bound, and a
/// whole-file read passes the type's maximum.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ByteRange {
    start: u64,
    len: u64,
}

impl ByteRange {
    /// `len` bytes from `start`, or `None` if the range would end past `u64::MAX`.
    #[must_use]
    pub const fn new(start: u64, len: u64) -> Option<Self> {
        match start.checked_add(len) {
            Some(_) => Some(Self { start, len }),
            None => None,
        }
    }

    /// The first `len` bytes. For a whole file, pass
    /// [`StoreKey::max_file_len`](crate::store_key::StoreKey::max_file_len).
    #[must_use]
    pub const fn prefix(len: u64) -> Self {
        Self { start: 0, len }
    }

    /// The offset of the first byte.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// The most bytes to read.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the range is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Checks a backend's answer: more bytes than asked for is
    /// [`BackendError::InvalidResponse`], as when a server ignores the range and sends the whole
    /// file. Fewer bytes mean the file ended; a caller that expected them maps that to
    /// [`FormatError::Truncated`](crate::format_error::FormatError::Truncated).
    ///
    /// # Errors
    ///
    /// [`BackendError::InvalidResponse`] if `bytes` is longer than the range.
    pub fn check_response(&self, bytes: &[u8]) -> Result<(), BackendError> {
        match u64::try_from(bytes.len()) {
            Ok(len) if len <= self.len => Ok(()),
            _ => Err(BackendError::InvalidResponse),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(ByteRange::new(u64::MAX, 1), None);
        let range = ByteRange::new(10, 2).expect("in range");
        assert_eq!((range.start(), range.len()), (10, 2));
        assert_eq!(range.check_response(b"ab"), Ok(()));
        assert_eq!(range.check_response(b"a"), Ok(()));
        assert_eq!(
            range.check_response(b"abc"),
            Err(BackendError::InvalidResponse)
        );
    }
}
