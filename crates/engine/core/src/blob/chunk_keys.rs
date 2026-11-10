//! The per-object keys of data blobs (FS-38).

use std::fmt;

use crypthix_crypto::kdf::{self, KdfContext};
use crypthix_crypto::key::{KdfKey, KeyError, MacKey, SealKey};
use crypthix_crypto::label::{MacKeyLabel, SealKeyLabel};
use crypthix_types::format_error::FormatError;

use crate::blob::BlobContext;

/// `K_chunk` and `K_blobid` of one object: derived from its DEK with its `dek_salt` under
/// `kdf/chunk-key` and `kdf/blob-id-key`, with context `vault_id ‖ object_id ‖ dek_id` (FS-38).
///
/// The keys keep the [`BlobContext`] they were derived for, which is also the fixed part of the
/// AAD of the object's data blobs (FS-55), so one object's keys are never used with another
/// object's AAD. [`ObjectSealer`](crate::blob::ObjectSealer) and
/// [`ObjectOpener`](crate::blob::ObjectOpener) seal and open with them.
pub struct ChunkKeys {
    chunk: SealKey,
    blob_id: MacKey,
    context: BlobContext,
}

impl ChunkKeys {
    /// Derives the keys of the object `context` names.
    ///
    /// # Errors
    ///
    /// - [`KeyError::Format`] with `ZeroValue` if `dek_salt` is all zero (FS-03).
    /// - [`KeyError::Memory`] if protected memory cannot be allocated for a key.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after `dek` was made.
    pub fn derive(
        dek: &KdfKey,
        dek_salt: &[u8; 32],
        context: BlobContext,
    ) -> Result<Self, KeyError> {
        if *dek_salt == [0u8; 32] {
            return Err(FormatError::ZeroValue.into());
        }
        let kdf_context = KdfContext::new()
            .field(context.vault_id().as_bytes())
            .field(context.object_id().as_bytes())
            .field(context.dek_id().as_bytes());
        let chunk = kdf::kdf(dek, Some(dek_salt), SealKeyLabel::ChunkKey, &kdf_context)?;
        let blob_id = kdf::kdf(dek, Some(dek_salt), MacKeyLabel::BlobIdKey, &kdf_context)?;
        Ok(Self {
            chunk,
            blob_id,
            context,
        })
    }

    /// The vault, object and DEK the keys were derived for.
    #[must_use]
    pub const fn context(&self) -> &BlobContext {
        &self.context
    }

    /// `K_chunk`, which seals the object's data blobs.
    #[must_use]
    pub const fn chunk_key(&self) -> &SealKey {
        &self.chunk
    }

    /// `K_blobid`, which keys the blob IDs of an ordinary object.
    #[must_use]
    pub const fn blob_id_key(&self) -> &MacKey {
        &self.blob_id
    }
}

/// Prints no key bytes.
impl fmt::Debug for ChunkKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChunkKeys(..)")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crypthix_types::id::{DekId, ObjectId, VaultId};

    use super::*;

    pub(crate) fn context(object: u8) -> BlobContext {
        BlobContext::new(
            VaultId::try_from_bytes([1; 16]).expect("non-zero"),
            ObjectId::try_from_bytes([object; 16]).expect("non-zero"),
            DekId::try_from_bytes([3; 16]).expect("non-zero"),
        )
    }

    pub(crate) fn keys(object: u8) -> ChunkKeys {
        let dek = KdfKey::from_bytes([9; 32]).expect("non-zero");
        ChunkKeys::derive(&dek, &[7; 32], context(object)).expect("derives")
    }

    #[test]
    fn keys_follow_the_fs_38_table() {
        let dek = KdfKey::from_bytes([9; 32]).expect("non-zero");
        let mut kdf_context = Vec::new();
        kdf_context.extend_from_slice(&[1; 16]);
        kdf_context.extend_from_slice(&[2; 16]);
        kdf_context.extend_from_slice(&[3; 16]);
        let kdf_context = KdfContext::from_bytes(kdf_context);
        let chunk: SealKey =
            kdf::kdf(&dek, Some(&[7; 32]), SealKeyLabel::ChunkKey, &kdf_context).expect("derives");
        let blob_id: MacKey =
            kdf::kdf(&dek, Some(&[7; 32]), MacKeyLabel::BlobIdKey, &kdf_context).expect("derives");
        let keys = keys(2);
        assert_eq!(keys.context(), &context(2));
        assert_eq!(keys.chunk_key().to_bytes(), chunk.to_bytes());
        assert_eq!(keys.blob_id_key().to_bytes(), blob_id.to_bytes());
        assert_ne!(chunk.to_bytes(), blob_id.to_bytes());
        assert_ne!(
            keys.chunk_key().to_bytes(),
            self::keys(4).chunk_key().to_bytes(),
            "the object ID is in the context"
        );
        assert_eq!(format!("{keys:?}"), "ChunkKeys(..)");
    }

    #[test]
    fn the_salt_is_used_and_may_not_be_zero() {
        let dek = KdfKey::from_bytes([9; 32]).expect("non-zero");
        let salted = ChunkKeys::derive(&dek, &[8; 32], context(2)).expect("derives");
        assert_ne!(
            salted.chunk_key().to_bytes(),
            keys(2).chunk_key().to_bytes()
        );
        assert_eq!(
            ChunkKeys::derive(&dek, &[0; 32], context(2)).map(|_| ()),
            Err(KeyError::Format(FormatError::ZeroValue))
        );
    }
}
