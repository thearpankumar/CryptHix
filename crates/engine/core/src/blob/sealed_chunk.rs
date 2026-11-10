//! A sealed data blob.

use std::fmt;

use crypthix_types::id::BlobId;

use crate::blob::ChunkEntry;

/// A data blob ready to be packed, with what the manifest records about it.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct SealedChunk {
    entry: ChunkEntry,
    sealed: Vec<u8>,
}

impl SealedChunk {
    pub(crate) const fn new(entry: ChunkEntry, sealed: Vec<u8>) -> Self {
        Self { entry, sealed }
    }

    /// The manifest entry: blob ID and `plain_len`.
    #[must_use]
    pub const fn entry(&self) -> &ChunkEntry {
        &self.entry
    }

    /// The blob ID.
    #[must_use]
    pub const fn blob_id(&self) -> &BlobId {
        self.entry.blob_id()
    }

    /// The sealed blob: `nonce ‖ C ‖ ciphertext ‖ tag`.
    #[must_use]
    pub fn sealed(&self) -> &[u8] {
        &self.sealed
    }

    /// The sealed blob, by value.
    #[must_use]
    pub fn into_sealed(self) -> Vec<u8> {
        self.sealed
    }
}

/// Prints the lengths only: not the ciphertext, and not the blob ID, which for a keyed ID is a
/// fingerprint of the chunk within its object (FS-55).
impl fmt::Debug for SealedChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedChunk")
            .field("plain_len", &self.entry.plain_len())
            .field("sealed_len", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_lengths_only() {
        let id = BlobId::try_from_bytes([0xab; 32]).expect("non-zero ID");
        let sealed = SealedChunk::new(ChunkEntry::new(id, 5), vec![0xcd; 7]);
        assert_eq!(
            format!("{sealed:?}"),
            "SealedChunk { plain_len: 5, sealed_len: 7, .. }"
        );
    }

    #[test]
    fn accessors_give_back_what_was_sealed() {
        let id = BlobId::try_from_bytes([0xab; 32]).expect("non-zero ID");
        let entry = ChunkEntry::new(id, 5);
        let sealed = SealedChunk::new(entry, vec![1, 2, 3]);
        assert_eq!(sealed.entry(), &entry);
        assert_eq!(sealed.blob_id(), &id);
        assert_eq!(sealed.sealed(), [1, 2, 3]);
        assert_eq!(sealed.into_sealed(), vec![1, 2, 3]);
    }
}
