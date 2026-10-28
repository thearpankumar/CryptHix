//! File metadata.

/// What a backend reports about a stored file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ObjectMeta {
    len: u64,
}

impl ObjectMeta {
    /// Metadata of a file of `len` bytes.
    #[must_use]
    pub const fn new(len: u64) -> Self {
        Self { len }
    }

    /// Size in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the file is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}
