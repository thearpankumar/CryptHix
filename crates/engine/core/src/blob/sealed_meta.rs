//! A sealed meta blob.

use std::fmt;

use crypthix_types::id::BlobId;

/// A meta blob ready to be packed, with its random blob ID.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct SealedMeta {
    blob_id: BlobId,
    sealed: Vec<u8>,
}

impl SealedMeta {
    pub(crate) const fn new(blob_id: BlobId, sealed: Vec<u8>) -> Self {
        Self { blob_id, sealed }
    }

    /// The blob ID.
    #[must_use]
    pub const fn blob_id(&self) -> &BlobId {
        &self.blob_id
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

/// Prints the length only, not the ciphertext or the blob ID.
impl fmt::Debug for SealedMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedMeta")
            .field("sealed_len", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_the_length_only() {
        let id = BlobId::try_from_bytes([0xab; 32]).expect("non-zero ID");
        let sealed = SealedMeta::new(id, vec![0xcd; 7]);
        assert_eq!(format!("{sealed:?}"), "SealedMeta { sealed_len: 7, .. }");
    }

    #[test]
    fn accessors_give_back_what_was_sealed() {
        let id = BlobId::try_from_bytes([0xab; 32]).expect("non-zero ID");
        let sealed = SealedMeta::new(id, vec![1, 2, 3]);
        assert_eq!(sealed.blob_id(), &id);
        assert_eq!(sealed.sealed(), [1, 2, 3]);
        assert_eq!(sealed.into_sealed(), vec![1, 2, 3]);
    }
}
