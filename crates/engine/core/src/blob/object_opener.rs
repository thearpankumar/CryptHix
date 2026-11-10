//! Opening the data blobs of one object (FS-55, FS-56).

use crypthix_crypto::cx_aead;
use crypthix_crypto::hash::Hash32;
use crypthix_crypto::mac;
use crypthix_crypto::secure_mem::SecretBuf;
use crypthix_types::format_error::FormatError;

use crate::blob::{BlobIdKind, ChunkEntry, ChunkKeys, ObjectClass, OpenedChunk, data_blob_aad};
use crate::compress::Decompressor;
use crate::error::ReadError;
use crate::inner::{Comp, decode_inner};
use crate::limits::MAX_PLAIN_LEN;

/// Opens the data blobs of one object, built once from the object's keys and the `class` and
/// `chunk_count` of its signed manifest (FS-55, FS-56).
///
/// The keys carry the [`BlobContext`](crate::blob::BlobContext) of the AAD, and the blob-ID
/// kind is derived here from the class and the count ([`BlobIdKind::for_object`]), so no call
/// can mix one object's keys with another's AAD or check a chunk under another kind.
#[derive(Debug)]
pub struct ObjectOpener<'k> {
    keys: &'k ChunkKeys,
    class: ObjectClass,
    blob_id_kind: BlobIdKind,
}

impl<'k> ObjectOpener<'k> {
    /// The opener of the object `keys` belong to, with the `class` and `chunk_count` its
    /// manifest records.
    #[must_use]
    pub const fn new(keys: &'k ChunkKeys, class: ObjectClass, chunk_count: u64) -> Self {
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

    /// Opens the data blob of `entry` and returns its plaintext.
    ///
    /// The checks run in this order, and the first failure is the error (FS-93); no plaintext
    /// is released before all of them pass:
    /// 1. `plain_len` is at most 1 MiB (`Decompress`), before anything is decrypted or
    ///    allocated;
    /// 2. the CX-AEAD open under `K_chunk` and the AAD of FS-55 (`Decrypt`, or `Truncated` /
    ///    `ZeroValue` for input too short to be a seal or with a zero nonce);
    /// 3. the inner plaintext (`Padding`, `Limit`, FS-54);
    /// 4. a secret-class object with `comp = 1` (`Padding`): its chunks are never compressed;
    /// 5. the payload: a raw one must be exactly `plain_len` bytes, a zstd one must pass every
    ///    frame check and decompress to exactly `plain_len` bytes (`Decompress`, FS-53);
    /// 6. a keyed blob ID must equal `MAC(K_blobid, plaintext)`, compared in constant time
    ///    (`Binding`, FS-56, FS-15). Random IDs have nothing to recompute.
    ///
    /// # Errors
    ///
    /// - [`ReadError::Format`] as above.
    /// - [`ReadError::Memory`] if protected memory cannot be allocated for the plaintext.
    /// - [`ReadError::Zstd`] if zstd cannot reset its context or runs out of memory.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the keys were made.
    pub fn open(
        &self,
        decompressor: &mut Decompressor,
        entry: &ChunkEntry,
        sealed: &[u8],
    ) -> Result<OpenedChunk, ReadError> {
        let plain_len = entry.plain_len();
        if plain_len > MAX_PLAIN_LEN {
            return Err(FormatError::Decompress.into());
        }
        let aad = data_blob_aad(self.keys.context(), entry.blob_id());
        let inner = cx_aead::open(self.keys.chunk_key(), &aad, sealed)?;
        let view = decode_inner(&inner)?;
        let opened = match (view.comp(), self.class) {
            (Comp::Zstd, ObjectClass::Secret) => return Err(FormatError::Padding.into()),
            (Comp::Raw, _) => {
                if view.payload().len() as u64 != plain_len {
                    return Err(FormatError::Decompress.into());
                }
                OpenedChunk::new(SecretBuf::try_copy_from(view.payload())?)
            }
            (Comp::Zstd, ObjectClass::Ordinary) => {
                OpenedChunk::new(decompressor.decode(view.payload(), plain_len)?)
            }
        };
        match self.blob_id_kind {
            BlobIdKind::Keyed => {
                let recomputed = mac::mac(self.keys.blob_id_key(), opened.as_slice());
                let stored = Hash32::try_from_bytes(*entry.blob_id().as_bytes())?;
                if recomputed != stored {
                    return Err(FormatError::Binding.into());
                }
            }
            BlobIdKind::Random => {}
        }
        Ok(opened)
    }
}

#[cfg(test)]
mod tests {
    use crypthix_crypto::cx_aead::NonceKind;
    use crypthix_types::id::{BlobId, DekId, ObjectId, VaultId};
    use proptest::collection::vec;
    use proptest::prelude::{any, prop_assert_eq, proptest};

    use super::*;
    use crate::blob::chunk_keys::tests::{context, keys};
    use crate::blob::{BlobContext, ObjectSealer};
    use crate::chunk::ObjectShape;
    use crate::compress::Compressor;
    use crate::inner::encode_inner;
    use crate::test_data::pseudo_random;

    fn text(len: usize) -> Vec<u8> {
        b"lorem ipsum dolor sit amet "
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    fn open(
        class: ObjectClass,
        count: u64,
        entry: &ChunkEntry,
        sealed: &[u8],
    ) -> Result<Vec<u8>, ReadError> {
        open_with(&keys(2), class, count, entry, sealed)
    }

    fn open_with(
        keys: &ChunkKeys,
        class: ObjectClass,
        count: u64,
        entry: &ChunkEntry,
        sealed: &[u8],
    ) -> Result<Vec<u8>, ReadError> {
        let mut decompressor = Decompressor::new();
        ObjectOpener::new(keys, class, count)
            .open(&mut decompressor, entry, sealed)
            .map(|opened| opened.as_slice().to_vec())
    }

    fn seal(class: ObjectClass, count: u64, chunk: &[u8]) -> (ChunkEntry, Vec<u8>) {
        let mut compressor = Compressor::new().expect("context");
        let keys = keys(2);
        let sealed = ObjectSealer::new(&keys, ObjectShape::new(class, count == 1))
            .seal(&mut compressor, chunk)
            .expect("seals");
        (*sealed.entry(), sealed.into_sealed())
    }

    /// A data blob sealed by hand around any inner plaintext.
    fn seal_inner(blob_id: &BlobId, inner: &[u8]) -> Vec<u8> {
        seal_inner_in(&context(2), blob_id, inner)
    }

    /// A data blob sealed by hand under the keys of object 2 and the AAD of `context`.
    fn seal_inner_in(context: &BlobContext, blob_id: &BlobId, inner: &[u8]) -> Vec<u8> {
        let aad = data_blob_aad(context, blob_id);
        cx_aead::seal(keys(2).chunk_key(), &aad, inner, NonceKind::Hedged).expect("seals")
    }

    /// The zstd frame of `chunk` as the compressor writes it.
    fn frame(chunk: &[u8]) -> Vec<u8> {
        let mut compressor = Compressor::new().expect("context");
        let inner = compressor
            .encode_chunk(chunk, ObjectClass::Ordinary)
            .expect("encodes");
        let view = decode_inner(&inner).expect("well formed");
        assert_eq!(view.comp(), Comp::Zstd, "test data compresses");
        view.payload().to_vec()
    }

    fn id(byte: u8) -> BlobId {
        BlobId::try_from_bytes([byte; 32]).expect("non-zero")
    }

    fn format(error: FormatError) -> Result<Vec<u8>, ReadError> {
        Err(ReadError::Format(error))
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn chunks_round_trip_for_every_class_and_kind() {
        for chunk in [text(200_000), pseudo_random(1, 100_000), b"x".to_vec()] {
            for (class, count) in [
                (ObjectClass::Ordinary, 1),
                (ObjectClass::Ordinary, 2),
                (ObjectClass::Secret, 1),
                (ObjectClass::Secret, 5),
            ] {
                let (entry, sealed) = seal(class, count, &chunk);
                assert_eq!(entry.plain_len(), chunk.len() as u64);
                assert_eq!(open(class, count, &entry, &sealed), Ok(chunk.clone()));
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn keyed_ids_repeat_within_an_object_and_random_ones_never() {
        let chunk = text(100_000);
        let (keyed, _) = seal(ObjectClass::Ordinary, 2, &chunk);
        let (again, _) = seal(ObjectClass::Ordinary, 3, &chunk);
        assert_eq!(
            keyed.blob_id(),
            again.blob_id(),
            "an unchanged chunk keeps its ID"
        );
        assert_eq!(
            keyed.blob_id().as_bytes(),
            mac::mac(keys(2).blob_id_key(), &chunk).as_bytes()
        );
        let other_object = keys(4);
        assert_ne!(
            keyed.blob_id().as_bytes(),
            mac::mac(other_object.blob_id_key(), &chunk).as_bytes(),
            "IDs are keyed per object"
        );
        for (class, count) in [(ObjectClass::Ordinary, 1), (ObjectClass::Secret, 2)] {
            let (first, _) = seal(class, count, &chunk);
            let (second, _) = seal(class, count, &chunk);
            assert_ne!(first.blob_id(), second.blob_id(), "{class:?} {count}");
        }
    }

    #[test]
    fn every_aad_field_is_bound() {
        let chunk = text(1_000);
        let decrypt = format(FormatError::Decrypt);
        let base = context(2);
        let vault = VaultId::try_from_bytes([9; 16]).expect("non-zero");
        let object = ObjectId::try_from_bytes([9; 16]).expect("non-zero");
        let dek = DekId::try_from_bytes([9; 16]).expect("non-zero");
        let changed = [
            BlobContext::new(vault, *base.object_id(), *base.dek_id()),
            BlobContext::new(*base.vault_id(), object, *base.dek_id()),
            BlobContext::new(*base.vault_id(), *base.object_id(), dek),
        ];
        // The inner plaintext of the chunk, sealed under the right key and a changed AAD.
        let inner = encode_inner(Comp::Raw, &chunk).expect("encodes");
        let keyed_id = BlobId::try_from_bytes(*mac::mac(keys(2).blob_id_key(), &chunk).as_bytes())
            .expect("non-zero");
        let keyed_entry = ChunkEntry::new(keyed_id, chunk.len() as u64);
        let (entry, sealed) = (keyed_entry, seal_inner(&keyed_id, &inner));
        assert_eq!(
            open(ObjectClass::Ordinary, 2, &entry, &sealed),
            Ok(chunk.clone()),
            "the right AAD opens"
        );
        for context in changed {
            let sealed = seal_inner_in(&context, &keyed_id, &inner);
            assert_eq!(
                open(ObjectClass::Ordinary, 2, &keyed_entry, &sealed),
                decrypt
            );
        }
        let other_id = ChunkEntry::new(id(9), entry.plain_len());
        assert_eq!(open(ObjectClass::Ordinary, 2, &other_id, &sealed), decrypt);
        let mut flipped = sealed.clone();
        flipped[100] ^= 1;
        assert_eq!(open(ObjectClass::Ordinary, 2, &entry, &flipped), decrypt);
        assert_eq!(
            open_with(&keys(4), ObjectClass::Ordinary, 2, &entry, &sealed),
            decrypt,
            "another object's keys"
        );
        assert_eq!(
            open(ObjectClass::Ordinary, 2, &entry, &sealed[..71]),
            format(FormatError::Truncated)
        );
    }

    #[test]
    fn plain_len_is_capped_before_the_blob_is_opened() {
        let garbage = vec![0x5A; 200];
        let at_cap = ChunkEntry::new(id(1), 1 << 20);
        assert_eq!(
            open(ObjectClass::Ordinary, 2, &at_cap, &garbage),
            format(FormatError::Decrypt)
        );
        let over = ChunkEntry::new(id(1), (1 << 20) + 1);
        assert_eq!(
            open(ObjectClass::Ordinary, 2, &over, &garbage),
            format(FormatError::Decompress)
        );
        assert_eq!(
            open(
                ObjectClass::Secret,
                1,
                &ChunkEntry::new(id(1), u64::MAX),
                &garbage
            ),
            format(FormatError::Decompress)
        );
    }

    #[test]
    fn a_keyed_id_that_does_not_match_the_plaintext_is_binding() {
        let chunk = b"chunk".to_vec();
        let inner = encode_inner(Comp::Raw, &chunk).expect("encodes");
        let sealed = seal_inner(&id(7), &inner);
        let entry = ChunkEntry::new(id(7), 5);
        assert_eq!(
            open(ObjectClass::Ordinary, 2, &entry, &sealed),
            format(FormatError::Binding)
        );
        // The same blob with a random ID: nothing to recompute.
        assert_eq!(
            open(ObjectClass::Ordinary, 1, &entry, &sealed),
            Ok(chunk.clone())
        );
        assert_eq!(open(ObjectClass::Secret, 2, &entry, &sealed), Ok(chunk));
    }

    #[test]
    fn bad_inner_plaintexts_are_padding_or_limit() {
        let entry = ChunkEntry::new(id(7), 5);
        let unpadded = seal_inner(&id(7), b"\x00\x00\x00\x00\x00\x05chunk");
        assert_eq!(
            open(ObjectClass::Ordinary, 1, &entry, &unpadded),
            format(FormatError::Padding)
        );
        let mut too_long = vec![0u8, 0];
        too_long.extend_from_slice(&((1u32 << 20) + 1).to_be_bytes());
        let sealed = seal_inner(&id(7), &too_long);
        assert_eq!(
            open(ObjectClass::Ordinary, 1, &entry, &sealed),
            format(FormatError::Limit)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn a_compressed_chunk_of_a_secret_object_is_padding() {
        let chunk = text(50_000);
        let inner = encode_inner(Comp::Zstd, &frame(&chunk)).expect("encodes");
        let sealed = seal_inner(&id(7), &inner);
        let entry = ChunkEntry::new(id(7), 50_000);
        assert_eq!(
            open(ObjectClass::Secret, 1, &entry, &sealed),
            format(FormatError::Padding)
        );
        assert_eq!(open(ObjectClass::Ordinary, 1, &entry, &sealed), Ok(chunk));
    }

    #[test]
    fn raw_payloads_must_be_exactly_plain_len_bytes() {
        let raw = seal_inner(&id(7), &encode_inner(Comp::Raw, b"chunk").expect("encodes"));
        for len in [0, 4, 6] {
            assert_eq!(
                open(ObjectClass::Ordinary, 1, &ChunkEntry::new(id(7), len), &raw),
                format(FormatError::Decompress),
                "{len}"
            );
        }
        assert_eq!(
            open(ObjectClass::Ordinary, 1, &ChunkEntry::new(id(7), 5), &raw),
            Ok(b"chunk".to_vec())
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn payloads_must_give_exactly_plain_len_bytes() {
        let chunk = text(50_000);
        let zstd = seal_inner(
            &id(7),
            &encode_inner(Comp::Zstd, &frame(&chunk)).expect("encodes"),
        );
        let raw = seal_inner(&id(7), &encode_inner(Comp::Raw, &chunk).expect("encodes"));
        for sealed in [&zstd, &raw] {
            for len in [49_999, 50_001] {
                let entry = ChunkEntry::new(id(7), len);
                assert_eq!(
                    open(ObjectClass::Ordinary, 1, &entry, sealed),
                    format(FormatError::Decompress),
                    "{len}"
                );
            }
        }
        let not_a_frame = seal_inner(
            &id(7),
            &encode_inner(Comp::Zstd, b"garbage").expect("encodes"),
        );
        let entry = ChunkEntry::new(id(7), 7);
        assert_eq!(
            open(ObjectClass::Ordinary, 1, &entry, &not_a_frame),
            format(FormatError::Decompress)
        );
    }

    #[test]
    fn debug_prints_no_plaintext() {
        let entry = ChunkEntry::new(id(7), 6);
        let sealed = seal_inner(
            &id(7),
            &encode_inner(Comp::Raw, b"secret").expect("encodes"),
        );
        let mut decompressor = Decompressor::new();
        let keys = keys(2);
        let chunk_opener = ObjectOpener::new(&keys, ObjectClass::Ordinary, 1);
        assert_eq!(chunk_opener.class(), ObjectClass::Ordinary);
        assert_eq!(chunk_opener.blob_id_kind(), BlobIdKind::Random);
        let opened = chunk_opener
            .open(&mut decompressor, &entry, &sealed)
            .expect("opens");
        assert_eq!(format!("{opened:?}"), "OpenedChunk(6 bytes)");
        assert!(!opened.is_empty());
        let printed = format!("{chunk_opener:?}");
        assert!(printed.contains("ChunkKeys(..)"), "{printed}");
    }

    #[test]
    fn an_empty_chunk_opens_empty() {
        let entry = ChunkEntry::new(id(7), 0);
        let sealed = seal_inner(&id(7), &encode_inner(Comp::Raw, b"").expect("encodes"));
        let keys = keys(2);
        let opened = ObjectOpener::new(&keys, ObjectClass::Ordinary, 1)
            .open(&mut Decompressor::new(), &entry, &sealed)
            .expect("opens");
        assert!(opened.is_empty());
        assert_eq!(opened.as_slice(), b"");
        assert_eq!(format!("{opened:?}"), "OpenedChunk(0 bytes)");
    }

    proptest! {
        #[test]
        #[cfg_attr(miri, ignore = "calls into libzstd")]
        fn seal_then_open_round_trips(
            chunk in vec(0u8..4, 1..20_000),
            secret in any::<bool>(),
            count in 1u64..4,
        ) {
            let class = if secret { ObjectClass::Secret } else { ObjectClass::Ordinary };
            let (entry, sealed) = seal(class, count, &chunk);
            prop_assert_eq!(open(class, count, &entry, &sealed), Ok(chunk));
        }
    }
}
