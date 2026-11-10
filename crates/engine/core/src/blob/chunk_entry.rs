//! What a manifest says about one chunk.

use std::fmt;

use crypthix_types::id::BlobId;

/// A chunk as its manifest lists it: its blob ID and its length before compression.
///
/// Its `Debug` shows only the length: a keyed blob ID is a MAC of the chunk's content (FS-55),
/// so even its first bytes are kept out of logs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkEntry {
    blob_id: BlobId,
    plain_len: u64,
}

impl ChunkEntry {
    /// An entry. `plain_len` is checked against the 1 MiB cap when the chunk is opened.
    #[must_use]
    pub const fn new(blob_id: BlobId, plain_len: u64) -> Self {
        Self { blob_id, plain_len }
    }

    /// The blob ID.
    #[must_use]
    pub const fn blob_id(&self) -> &BlobId {
        &self.blob_id
    }

    /// The chunk's length before compression.
    #[must_use]
    pub const fn plain_len(&self) -> u64 {
        self.plain_len
    }
}

/// Prints the length, not the blob ID.
impl fmt::Debug for ChunkEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkEntry")
            .field("plain_len", &self.plain_len)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_the_length_and_no_byte_of_the_blob_id() {
        let id = BlobId::try_from_bytes([0xef; 32]).expect("non-zero ID");
        let entry = ChunkEntry::new(id, 4_096);
        let printed = format!("{entry:?}");
        assert_eq!(printed, "ChunkEntry { plain_len: 4096, .. }");
        assert!(!printed.contains("ef"), "{printed}");
    }
}
