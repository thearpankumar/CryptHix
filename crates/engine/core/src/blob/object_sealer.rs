//! Sealing the chunks of one object as data blobs (FS-55).

use std::ptr;

use crypthix_crypto::cx_aead::{self, NonceKind};
use crypthix_crypto::mac;
use crypthix_crypto::random;
use crypthix_types::id::BlobId;

use crate::blob::{
    self, BlobIdKind, ChunkEntry, ChunkKeys, IdentifiedChunk, ObjectClass, SealedChunk,
};
use crate::chunk::{ChunkRef, ObjectShape};
use crate::compress::Compressor;
use crate::error::WriteError;

/// Seals the chunks of one object as data blobs (FS-53 to FS-55): compressed where it pays and
/// never for the secret class, padded with Padmé, and sealed under the object's `K_chunk` with
/// a hedged nonce and the AAD of the [`BlobContext`](crate::blob::BlobContext) its keys were
/// derived for.
///
/// It is built once per object from the object's keys and the [`ObjectShape`] its chunker gave.
/// The blob IDs are keyed, `MAC(K_blobid, chunk)`, exactly for an ordinary object of two or more
/// chunks, and random otherwise ([`BlobIdKind::for_object`]). What it enforces:
///
/// - every chunk it takes is a [`ChunkRef`], which only the chunker makes, of the sealer's
///   shape: a chunk the chunker cut as an object's only chunk, or cut for the other class, is
///   refused, so no keyed ID is ever computed for it (T-85) and no secret chunk is compressed
///   (T-40);
/// - [`seal`](Self::seal), [`seal_identified`](Self::seal_identified) and
///   [`reuse`](Self::reuse) take chunks 0, 1, 2… in order, and none after the last;
/// - [`finish`](Self::finish) fails unless the last chunk was taken (or the shape has no
///   chunk), and gives the chunk count the manifest must record: exactly one for a single
///   shape, two or more for any other.
///
/// It does not check that consecutive chunks come from the same chunker: two objects of the
/// same shape could be interleaved. Blobs sealed before a failed `finish` must not be stored.
///
/// The chunks of one object that are equal get the same keyed ID, so a writer must store one
/// blob per ID: on an ID already stored in this version or the last, it calls `reuse` instead
/// of sealing again (E1).
#[derive(Debug)]
pub struct ObjectSealer<'k> {
    keys: &'k ChunkKeys,
    shape: ObjectShape,
    blob_id_kind: BlobIdKind,
    /// Chunks taken so far, sealed or reused: the index the next one must have.
    taken: u64,
    /// The object's last chunk has been taken.
    complete: bool,
}

impl<'k> ObjectSealer<'k> {
    /// The sealer of the object `keys` belong to, whose chunker gave `shape`
    /// ([`ChunkRef::object_shape`] or
    /// [`Chunks::object_shape`](crate::chunk::Chunks::object_shape)); the object's class is
    /// the one it was cut for.
    #[must_use]
    pub const fn new(keys: &'k ChunkKeys, shape: ObjectShape) -> Self {
        Self {
            keys,
            shape,
            blob_id_kind: BlobIdKind::for_object(shape.class(), shape.kind_count()),
            taken: 0,
            complete: false,
        }
    }

    /// The object's class.
    #[must_use]
    pub const fn class(&self) -> ObjectClass {
        self.shape.class()
    }

    /// How the object's blob IDs are made.
    #[must_use]
    pub const fn blob_id_kind(&self) -> BlobIdKind {
        self.blob_id_kind
    }

    /// Works out the keyed blob ID of `chunk` before it is sealed, so a writer can look it up
    /// among the blobs already stored (E1). The ID is `None` if the object's blob IDs are
    /// random. Pass the result to [`seal_identified`](Self::seal_identified) or
    /// [`reuse`](Self::reuse) of this sealer.
    ///
    /// # Errors
    ///
    /// - [`WriteError::Sequence`] if `chunk` is not of the sealer's shape.
    /// - [`WriteError::Format`] with `ZeroValue` if the keyed ID came out all zero (FS-03).
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the keys were made.
    pub fn identify<'c>(&self, chunk: ChunkRef<'c>) -> Result<IdentifiedChunk<'k, 'c>, WriteError> {
        if chunk.object_shape() != self.shape {
            return Err(WriteError::Sequence);
        }
        let keyed_id = match self.blob_id_kind {
            BlobIdKind::Keyed => {
                let mac = mac::mac(self.keys.blob_id_key(), chunk.bytes());
                Some(BlobId::try_from_bytes(*mac.as_bytes())?)
            }
            BlobIdKind::Random => None,
        };
        Ok(IdentifiedChunk::new(self.keys, chunk, keyed_id))
    }

    /// Seals the next chunk of the object: [`identify`](Self::identify), then
    /// [`seal_identified`](Self::seal_identified).
    ///
    /// # Errors
    ///
    /// As those two.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the keys were made.
    pub fn seal(
        &mut self,
        compressor: &mut Compressor,
        chunk: ChunkRef<'_>,
    ) -> Result<SealedChunk, WriteError> {
        let identified = self.identify(chunk)?;
        self.seal_identified(compressor, identified)
    }

    /// Seals the next chunk of the object under the blob ID [`identify`](Self::identify) gave
    /// it, or a random one drawn now.
    ///
    /// # Errors
    ///
    /// - [`WriteError::Sequence`] if `identified` comes from a sealer of other keys, or is not
    ///   the next chunk of an object of this sealer's shape.
    /// - [`WriteError::Format`] with `Limit` if the chunk is longer than 1 MiB, or `ZeroValue`
    ///   if a random blob ID came out all zero (FS-03).
    /// - [`WriteError::Random`] if the kernel gives no random blob ID.
    /// - [`WriteError::Zstd`] if zstd fails; the chunk is then not stored raw instead.
    /// - [`WriteError::Seal`] if the seal fails.
    /// - [`WriteError::Memory`] if protected memory cannot be allocated for the inner plaintext.
    ///
    /// On any error the sealer does not move on, so the same chunk can be given again.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the keys were made.
    pub fn seal_identified(
        &mut self,
        compressor: &mut Compressor,
        identified: IdentifiedChunk<'_, '_>,
    ) -> Result<SealedChunk, WriteError> {
        let (keys, chunk, keyed_id) = identified.into_parts();
        self.check_next(keys, chunk)?;
        let inner = compressor.encode_chunk(chunk.bytes(), self.class())?;
        let blob_id = match keyed_id {
            Some(keyed) => keyed,
            None => BlobId::try_from_bytes(random::bytes::<32>()?)?,
        };
        let aad = blob::data_blob_aad(self.keys.context(), &blob_id);
        let sealed = cx_aead::seal(self.keys.chunk_key(), &aad, &inner, NonceKind::Hedged)?;
        self.advance(chunk);
        let entry = ChunkEntry::new(blob_id, chunk.bytes().len() as u64);
        Ok(SealedChunk::new(entry, sealed))
    }

    /// Takes the next chunk of the object without sealing it, because a blob of its keyed ID
    /// is already stored, and returns what the manifest records for it (E1, FS-55).
    ///
    /// # Errors
    ///
    /// [`WriteError::Sequence`] as for [`seal_identified`](Self::seal_identified), or if the
    /// object's blob IDs are random: such blobs are never reused. The sealer then does not move
    /// on.
    pub fn reuse(&mut self, identified: IdentifiedChunk<'_, '_>) -> Result<ChunkEntry, WriteError> {
        let (keys, chunk, keyed_id) = identified.into_parts();
        self.check_next(keys, chunk)?;
        let Some(blob_id) = keyed_id else {
            return Err(WriteError::Sequence);
        };
        let entry = ChunkEntry::new(blob_id, chunk.bytes().len() as u64);
        self.advance(chunk);
        Ok(entry)
    }

    /// Ends the object and returns the chunk count its manifest must record.
    ///
    /// # Errors
    ///
    /// [`WriteError::Sequence`] if the object's last chunk was not taken; an empty object, of
    /// no chunk, has none to take. Then the object is incomplete, and nothing sealed for it may
    /// be stored.
    pub fn finish(self) -> Result<u64, WriteError> {
        if self.complete || self.shape.is_empty() {
            Ok(self.taken)
        } else {
            Err(WriteError::Sequence)
        }
    }

    /// Whether `chunk`, identified under `keys`, is the next chunk of this object, identified
    /// under this sealer's keys.
    fn check_next(&self, keys: &ChunkKeys, chunk: ChunkRef<'_>) -> Result<(), WriteError> {
        let next = ptr::eq(keys, self.keys)
            && chunk.object_shape() == self.shape
            && chunk.index() == self.taken
            && !self.complete;
        if next {
            Ok(())
        } else {
            Err(WriteError::Sequence)
        }
    }

    /// Moves on past `chunk`, which was sealed or reused.
    fn advance(&mut self, chunk: ChunkRef<'_>) {
        self.taken = self.taken.saturating_add(1);
        self.complete = chunk.is_last();
    }
}

#[cfg(test)]
mod tests {
    use crypthix_crypto::secure_mem::MemError;

    use super::*;
    use crate::blob::chunk_keys::tests::keys;
    use crate::chunk::ChunkCount;
    use crate::compress::CompressError;
    use crate::fault::{self, Fault};

    const SEQUENCE: Result<u64, WriteError> = Err(WriteError::Sequence);

    fn shape(class: ObjectClass, count: ChunkCount) -> ObjectShape {
        ObjectShape::new(class, count)
    }

    /// Chunk `index` of an object of `class` with `total` chunks.
    fn chunk(class: ObjectClass, index: u64, total: u64) -> ChunkRef<'static> {
        ChunkRef::new(b"chunk bytes", index, index + 1 == total, class)
    }

    /// Seals chunk `index` of an object of `class` and `total` chunks, keeping only the error.
    fn seal(
        sealer: &mut ObjectSealer<'_>,
        class: ObjectClass,
        index: u64,
        total: u64,
    ) -> Result<(), WriteError> {
        let mut compressor = Compressor::new().expect("context");
        sealer
            .seal(&mut compressor, chunk(class, index, total))
            .map(|_| ())
    }

    #[test]
    fn the_kind_follows_the_class_and_the_chunkers_shape() {
        let keys = keys(2);
        let cases = [
            (ObjectClass::Ordinary, ChunkCount::Many, BlobIdKind::Keyed),
            (ObjectClass::Ordinary, ChunkCount::One, BlobIdKind::Random),
            (ObjectClass::Ordinary, ChunkCount::Zero, BlobIdKind::Random),
            (ObjectClass::Secret, ChunkCount::Many, BlobIdKind::Random),
            (ObjectClass::Secret, ChunkCount::One, BlobIdKind::Random),
        ];
        for (class, count, kind) in cases {
            let sealer = ObjectSealer::new(&keys, shape(class, count));
            assert_eq!(sealer.blob_id_kind(), kind, "{class:?} {count:?}");
            assert_eq!(sealer.class(), class);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "makes a zstd context")]
    fn finish_gives_the_count_only_once_the_last_chunk_is_sealed() {
        let keys = keys(2);
        let secret = ObjectClass::Secret;
        let mut whole = ObjectSealer::new(&keys, shape(secret, ChunkCount::Many));
        for index in 0..3 {
            seal(&mut whole, secret, index, 3).expect("seals");
        }
        assert_eq!(whole.finish(), Ok(3));

        let mut short = ObjectSealer::new(&keys, shape(secret, ChunkCount::Many));
        for index in 0..2 {
            seal(&mut short, secret, index, 3).expect("seals");
        }
        assert_eq!(short.finish(), SEQUENCE, "the last chunk is missing");

        let mut single = ObjectSealer::new(&keys, shape(secret, ChunkCount::One));
        seal(&mut single, secret, 0, 1).expect("seals");
        assert_eq!(single.finish(), Ok(1));

        for count in [ChunkCount::One, ChunkCount::Many] {
            let untouched = ObjectSealer::new(&keys, shape(secret, count));
            assert_eq!(untouched.finish(), SEQUENCE, "{count:?}: nothing sealed");
        }
        let empty = ObjectSealer::new(&keys, shape(secret, ChunkCount::Zero));
        assert_eq!(
            empty.finish(),
            Ok(0),
            "an empty object has no chunk to seal"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "makes a zstd context")]
    fn chunks_out_of_order_or_past_the_last_are_refused() {
        let keys = keys(2);
        let secret = ObjectClass::Secret;
        let mut sealer = ObjectSealer::new(&keys, shape(secret, ChunkCount::Many));
        assert_eq!(
            seal(&mut sealer, secret, 1, 3),
            Err(WriteError::Sequence),
            "skips chunk 0"
        );
        seal(&mut sealer, secret, 0, 3).expect("the refusal did not move the sealer on");
        assert_eq!(
            seal(&mut sealer, secret, 0, 3),
            Err(WriteError::Sequence),
            "chunk 0 again"
        );
        seal(&mut sealer, secret, 1, 2).expect("seals the last chunk");
        assert_eq!(
            seal(&mut sealer, secret, 2, 3),
            Err(WriteError::Sequence),
            "a chunk after the last"
        );
        assert_eq!(sealer.finish(), Ok(2));
    }

    #[test]
    #[cfg_attr(miri, ignore = "makes a zstd context")]
    fn a_chunk_of_another_shape_is_refused() {
        let keys = keys(2);
        let (ordinary, secret) = (ObjectClass::Ordinary, ObjectClass::Secret);
        let mut multiple = ObjectSealer::new(&keys, shape(ordinary, ChunkCount::Many));
        assert_eq!(
            multiple.identify(chunk(ordinary, 0, 1)).map(|_| ()),
            Err(WriteError::Sequence),
            "no keyed ID for an object's only chunk"
        );
        assert_eq!(
            seal(&mut multiple, ordinary, 0, 1),
            Err(WriteError::Sequence)
        );
        assert_eq!(
            seal(&mut multiple, secret, 0, 2),
            Err(WriteError::Sequence),
            "class"
        );
        let mut single = ObjectSealer::new(&keys, shape(ordinary, ChunkCount::One));
        assert_eq!(seal(&mut single, ordinary, 0, 2), Err(WriteError::Sequence));
        let mut empty = ObjectSealer::new(&keys, shape(ordinary, ChunkCount::Zero));
        assert_eq!(seal(&mut empty, ordinary, 0, 1), Err(WriteError::Sequence));
    }

    #[test]
    #[cfg_attr(miri, ignore = "makes a zstd context")]
    fn only_the_sealer_of_the_same_keys_and_shape_takes_an_identified_chunk() {
        let (keys, other_keys) = (keys(2), keys(4));
        let secret = ObjectClass::Secret;
        let mut compressor = Compressor::new().expect("context");
        let mut sealer = ObjectSealer::new(&keys, shape(secret, ChunkCount::Many));
        let other = ObjectSealer::new(&other_keys, shape(secret, ChunkCount::Many));
        let foreign = other.identify(chunk(secret, 0, 2)).expect("identifies");
        assert_eq!(
            sealer.seal_identified(&mut compressor, foreign).map(|_| ()),
            Err(WriteError::Sequence),
            "another object's keys"
        );
        let single = ObjectSealer::new(&keys, shape(secret, ChunkCount::One));
        let only = single.identify(chunk(secret, 0, 1)).expect("identifies");
        assert_eq!(
            sealer.seal_identified(&mut compressor, only).map(|_| ()),
            Err(WriteError::Sequence),
            "the same keys, another shape"
        );
        let own = sealer.identify(chunk(secret, 0, 2)).expect("identifies");
        assert_eq!(own.keyed_id(), None, "secret IDs are random");
        let blob = sealer.seal_identified(&mut compressor, own).expect("seals");
        assert_eq!(blob.entry().plain_len(), 11);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_keyed_id_is_worked_out_once_and_sealed_or_reused() {
        let keys = keys(2);
        let ordinary = ObjectClass::Ordinary;
        let mut compressor = Compressor::new().expect("context");
        let mut sealer = ObjectSealer::new(&keys, shape(ordinary, ChunkCount::Many));
        let first = sealer.identify(chunk(ordinary, 0, 3)).expect("identifies");
        let expected =
            BlobId::try_from_bytes(*mac::mac(keys.blob_id_key(), b"chunk bytes").as_bytes())
                .expect("non-zero");
        assert_eq!(first.keyed_id(), Some(&expected));
        let blob = sealer
            .seal_identified(&mut compressor, first)
            .expect("seals");
        assert_eq!(blob.blob_id(), &expected);

        // An equal chunk later in the object has the same ID, so its blob is reused.
        let again = sealer.identify(chunk(ordinary, 1, 3)).expect("identifies");
        assert_eq!(again.keyed_id(), Some(&expected));
        let entry = sealer.reuse(again).expect("reuses");
        assert_eq!(entry, ChunkEntry::new(expected, 11));
        let last = sealer
            .seal(&mut compressor, chunk(ordinary, 2, 3))
            .expect("seals");
        assert_eq!(last.blob_id(), &expected);
        assert_eq!(sealer.finish(), Ok(3));
    }

    #[test]
    #[cfg_attr(miri, ignore = "makes a zstd context")]
    fn a_random_id_is_never_reused() {
        let keys = keys(2);
        let secret = ObjectClass::Secret;
        let mut sealer = ObjectSealer::new(&keys, shape(secret, ChunkCount::One));
        let identified = sealer.identify(chunk(secret, 0, 1)).expect("identifies");
        assert_eq!(sealer.reuse(identified), Err(WriteError::Sequence));
        seal(&mut sealer, secret, 0, 1).expect("the refusal did not move the sealer on");
        assert_eq!(sealer.finish(), Ok(1));
    }

    #[test]
    #[cfg_attr(miri, ignore = "makes a zstd context")]
    fn no_protected_memory_for_the_inner_plaintext_fails_and_the_sealer_stays() {
        let keys = keys(2);
        let mut compressor = Compressor::new().expect("context");
        for class in [ObjectClass::Ordinary, ObjectClass::Secret] {
            let mut sealer = ObjectSealer::new(&keys, shape(class, ChunkCount::Many));
            {
                let _guard = fault::inject(Fault::Allocation(0));
                assert_eq!(
                    sealer.seal(&mut compressor, chunk(class, 0, 2)).map(|_| ()),
                    Err(WriteError::Memory(MemError::MapFailed)),
                    "{class:?}"
                );
                assert!(fault::fired(), "{class:?}");
            }
            seal(&mut sealer, class, 0, 2).expect("the failure did not move the sealer on");
            seal(&mut sealer, class, 1, 2).expect("seals");
            assert_eq!(sealer.finish(), Ok(2));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "makes a zstd context")]
    fn a_zstd_error_fails_the_seal_and_the_sealer_stays() {
        let keys = keys(2);
        let mut compressor = Compressor::new().expect("context");
        let class = ObjectClass::Ordinary;
        let mut sealer = ObjectSealer::new(&keys, shape(class, ChunkCount::Many));
        {
            let _guard = fault::inject(Fault::Compress(0usize.wrapping_sub(1)));
            assert!(matches!(
                sealer.seal(&mut compressor, chunk(class, 0, 2)),
                Err(WriteError::Zstd(CompressError::Zstd(_)))
            ));
        }
        seal(&mut sealer, class, 0, 2).expect("the failure did not move the sealer on");
    }
}
