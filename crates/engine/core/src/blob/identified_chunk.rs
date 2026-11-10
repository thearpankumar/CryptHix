//! A chunk with the blob ID its sealer worked out for it.

use std::fmt;

use crypthix_types::id::BlobId;

use crate::blob::ChunkKeys;
use crate::chunk::ChunkRef;

/// A chunk of an object with its keyed blob ID, if the object's blob IDs are keyed, from
/// [`ObjectSealer::identify`](crate::blob::ObjectSealer::identify).
///
/// A writer looks the keyed ID up among the blobs already stored, then hands the chunk back to
/// the same sealer: to [`reuse`](crate::blob::ObjectSealer::reuse) if a blob of that ID is
/// there, to [`seal_identified`](crate::blob::ObjectSealer::seal_identified) if not, which
/// seals under this ID without computing the MAC again. Only a sealer makes one, and only the
/// sealer of the same keys takes it back, so the ID is never the caller's.
pub struct IdentifiedChunk<'k, 'c> {
    keys: &'k ChunkKeys,
    chunk: ChunkRef<'c>,
    keyed_id: Option<BlobId>,
}

impl<'k, 'c> IdentifiedChunk<'k, 'c> {
    pub(crate) const fn new(
        keys: &'k ChunkKeys,
        chunk: ChunkRef<'c>,
        keyed_id: Option<BlobId>,
    ) -> Self {
        Self {
            keys,
            chunk,
            keyed_id,
        }
    }

    /// The keyed blob ID `MAC(K_blobid, chunk)`, or `None` if the object's blob IDs are random:
    /// those are drawn when the chunk is sealed and never reused (FS-55).
    #[must_use]
    pub const fn keyed_id(&self) -> Option<&BlobId> {
        self.keyed_id.as_ref()
    }

    /// The chunk.
    #[must_use]
    pub const fn chunk(&self) -> ChunkRef<'c> {
        self.chunk
    }

    /// The keys of the sealer that identified the chunk, the chunk, and its keyed ID; consumed
    /// so that one identification seals or reuses one chunk.
    pub(crate) const fn into_parts(self) -> (&'k ChunkKeys, ChunkRef<'c>, Option<BlobId>) {
        (self.keys, self.chunk, self.keyed_id)
    }
}

/// Prints the chunk's position and length only: not its bytes, and not its keyed ID, which is
/// a fingerprint of the chunk within its object (FS-55).
impl fmt::Debug for IdentifiedChunk<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentifiedChunk")
            .field("chunk", &self.chunk)
            .field("keyed", &self.keyed_id.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::ObjectClass;
    use crate::blob::chunk_keys::tests::keys;

    #[test]
    fn debug_shows_no_bytes_and_no_id() {
        let keys = keys(2);
        let id = BlobId::try_from_bytes([0xef; 32]).expect("non-zero ID");
        let chunk = ChunkRef::new(b"secret", 1, false, ObjectClass::Ordinary);
        let identified = IdentifiedChunk::new(&keys, chunk, Some(id));
        assert_eq!(identified.keyed_id(), Some(&id));
        assert_eq!(identified.chunk().bytes(), b"secret");
        assert_eq!(
            format!("{identified:?}"),
            "IdentifiedChunk { chunk: ChunkRef { len: 6, index: 1, is_last: false }, keyed: true, .. }"
        );
    }
}
