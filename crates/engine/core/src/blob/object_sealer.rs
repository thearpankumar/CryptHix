//! Sealing the chunks of one object as data blobs (FS-55).

use crypthix_crypto::cx_aead::{self, NonceKind};
use crypthix_crypto::mac;
use crypthix_crypto::random;
use crypthix_types::id::BlobId;

use crate::blob::{BlobIdKind, ChunkEntry, ChunkKeys, ObjectClass, SealedChunk, data_blob_aad};
use crate::chunk::ObjectShape;
use crate::compress::Compressor;
use crate::error::WriteError;

/// Seals the chunks of one object as data blobs (FS-53 to FS-55): compressed where it pays and
/// never for the secret class, padded with Padmé, and sealed under the object's `K_chunk` with
/// a hedged nonce and the AAD of the [`BlobContext`](crate::blob::BlobContext) its keys were
/// derived for.
///
/// It is built once per object from the object's keys and its [`ObjectShape`], which only the
/// chunker gives and which carries the class the object was cut for, so an object is sealed in
/// the class it was cut in. The blob IDs are keyed, `MAC(K_blobid, chunk)`, exactly for an
/// ordinary object of two or more chunks, and random otherwise ([`BlobIdKind::for_object`]),
/// so no caller can give a single-chunk object keyed IDs (T-85).
#[derive(Debug)]
pub struct ObjectSealer<'k> {
    keys: &'k ChunkKeys,
    class: ObjectClass,
    blob_id_kind: BlobIdKind,
}

impl<'k> ObjectSealer<'k> {
    /// The sealer of the object `keys` belong to, whose chunker gave `shape`
    /// ([`ChunkRef::object_shape`](crate::chunk::ChunkRef::object_shape) or
    /// [`Chunks::object_shape`](crate::chunk::Chunks::object_shape)); the object's class is
    /// the one it was cut for.
    #[must_use]
    pub const fn new(keys: &'k ChunkKeys, shape: ObjectShape) -> Self {
        let class = shape.class();
        let chunk_count = if shape.is_single() { 1 } else { 2 };
        Self {
            keys,
            class,
            blob_id_kind: BlobIdKind::for_object(class, chunk_count),
        }
    }

    /// The object's class.
    #[must_use]
    pub const fn class(&self) -> ObjectClass {
        self.class
    }

    /// How the object's blob IDs are made.
    #[must_use]
    pub const fn blob_id_kind(&self) -> BlobIdKind {
        self.blob_id_kind
    }

    /// Seals one chunk of the object.
    ///
    /// # Errors
    ///
    /// - [`WriteError::Format`] with `Limit` if `chunk` is longer than 1 MiB, or `ZeroValue` if
    ///   a blob ID came out all zero (FS-03).
    /// - [`WriteError::Random`] if the kernel gives no random blob ID.
    /// - [`WriteError::Zstd`] if zstd fails; the chunk is then not stored raw instead.
    /// - [`WriteError::Seal`] if the seal fails.
    /// - [`WriteError::Memory`] if protected memory cannot be allocated for the inner plaintext.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the keys were made.
    pub fn seal(
        &self,
        compressor: &mut Compressor,
        chunk: &[u8],
    ) -> Result<SealedChunk, WriteError> {
        let inner = compressor.encode_chunk(chunk, self.class)?;
        let id_bytes = match self.blob_id_kind {
            BlobIdKind::Keyed => *mac::mac(self.keys.blob_id_key(), chunk).as_bytes(),
            BlobIdKind::Random => random::bytes::<32>()?,
        };
        let blob_id = BlobId::try_from_bytes(id_bytes)?;
        let aad = data_blob_aad(self.keys.context(), &blob_id);
        let sealed = cx_aead::seal(self.keys.chunk_key(), &aad, &inner, NonceKind::Hedged)?;
        let entry = ChunkEntry::new(blob_id, chunk.len() as u64);
        Ok(SealedChunk::new(entry, sealed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::chunk_keys::tests::keys;

    #[test]
    fn the_kind_follows_the_class_and_the_chunkers_shape() {
        let keys = keys(2);
        let cases = [
            (ObjectClass::Ordinary, false, BlobIdKind::Keyed),
            (ObjectClass::Ordinary, true, BlobIdKind::Random),
            (ObjectClass::Secret, false, BlobIdKind::Random),
            (ObjectClass::Secret, true, BlobIdKind::Random),
        ];
        for (class, single, kind) in cases {
            let sealer = ObjectSealer::new(&keys, ObjectShape::new(class, single));
            assert_eq!(sealer.blob_id_kind(), kind, "{class:?} {single}");
            assert_eq!(sealer.class(), class);
        }
    }
}
