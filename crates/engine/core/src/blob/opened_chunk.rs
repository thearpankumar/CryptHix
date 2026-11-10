//! An opened data blob.

use std::fmt;

use crypthix_crypto::secure_mem::SecretBuf;

/// A chunk's plaintext in protected memory, released only after every check of
/// [`ObjectOpener::open`](crate::blob::ObjectOpener::open) passed (FS-93).
pub struct OpenedChunk {
    /// Exactly the plaintext, so reading it cannot fail.
    plain: SecretBuf,
    /// `plain.len()`, kept so the length can be had without reading the buffer.
    len: usize,
}

impl OpenedChunk {
    /// `plain` is the whole plaintext. A raw chunk is copied out of its inner plaintext, whose
    /// header and padding are then wiped with it.
    pub(crate) fn new(plain: SecretBuf) -> Self {
        let len = plain.len();
        Self { plain, len }
    }

    /// The plaintext.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the chunk was opened.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.plain.as_slice()
    }

    /// The plaintext's length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the plaintext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Prints the length, never the plaintext.
impl fmt::Debug for OpenedChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpenedChunk({} bytes)", self.len())
    }
}
