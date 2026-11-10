//! Opening data blobs on hostile input (FS-53 to FS-56).
//!
//! Random bytes under fixed keys only reach the length, nonce and AEAD checks, since they never
//! authenticate. So the target also seals the input as an inner plaintext under the blob's own
//! key and AAD, which takes it past the AEAD to the inner-plaintext, frame and blob-ID checks,
//! and checks each against what that stage alone says. Last, it writes the input as a chunk,
//! opens it, and flips one byte the input chooses.

use std::cell::RefCell;

use crypthix_core::blob::{
    BlobContext, ChunkEntry, ChunkKeys, ObjectClass, ObjectOpener, ObjectSealer, data_blob_aad,
};
use crypthix_core::chunk::{Chunks, GearTable, ObjectShape};
use crypthix_core::compress::{Compressor, Decompressor};
use crypthix_core::error::ReadError;
use crypthix_core::inner::{self, Comp};
use crypthix_core::limits::{MAX_CHUNK, MAX_PLAIN_LEN};
use crypthix_crypto::cx_aead::{self, NONCE_LEN, OVERHEAD};
use crypthix_crypto::key::KdfKey;
use crypthix_crypto::mac;
use crypthix_types::format_error::FormatError;
use crypthix_types::id::{BlobId, DekId, ObjectId, VaultId};

thread_local! {
    static COMPRESSOR: RefCell<Compressor> = RefCell::new(Compressor::new().expect("a zstd context"));
    static DECOMPRESSOR: RefCell<Decompressor> = RefCell::new(Decompressor::new());
    /// The shapes the chunker gives an ordinary and a secret object of two or more chunks.
    static MULTIPLE: [ObjectShape; 2] = shapes(MAX_CHUNK + 1);
    /// The shapes the chunker gives an ordinary and a secret object of one chunk.
    static SINGLE: [ObjectShape; 2] = shapes(1);
}

/// The shapes the chunker gives `len` zero bytes in an ordinary and in a secret object; only
/// the chunker makes shapes.
fn shapes(len: usize) -> [ObjectShape; 2] {
    let seed = KdfKey::from_bytes([1; 32]).expect("non-zero key");
    let vault_id = VaultId::try_from_bytes([1; 16]).expect("non-zero ID");
    let gear = GearTable::derive(&seed, &vault_id).expect("derives");
    let zeros = vec![0; len];
    [ObjectClass::Ordinary, ObjectClass::Secret]
        .map(|class| Chunks::new(&gear, class, &zeros).object_shape())
}

/// The shape of an object of `class` and `count` chunks.
fn shape_of(class: ObjectClass, count: u64) -> ObjectShape {
    let index = usize::from(class == ObjectClass::Secret);
    let shape = if count == 1 {
        SINGLE.with(|shapes| shapes[index])
    } else {
        MULTIPLE.with(|shapes| shapes[index])
    };
    assert_eq!(
        (shape.class(), shape.is_single()),
        (class, count == 1),
        "the chunker's shape of {count} chunks"
    );
    shape
}

/// The fixed nonce the target seals inner plaintexts with; never all zero (FS-03).
const NONCE: [u8; NONCE_LEN] = [1; NONCE_LEN];

/// A blob ID no chunk of these keys has.
const OTHER_ID: [u8; 32] = [5; 32];

fn id(bytes: [u8; 32]) -> BlobId {
    BlobId::try_from_bytes(bytes).expect("non-zero ID")
}

/// One open of `sealed` as a chunk of an object of `class` with `count` chunks.
fn open(
    keys: &ChunkKeys,
    (class, count): (ObjectClass, u64),
    entry: &ChunkEntry,
    sealed: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let reader = ObjectOpener::new(keys, class, count);
    let result =
        DECOMPRESSOR.with_borrow_mut(|decompressor| reader.open(decompressor, entry, sealed));
    match result {
        Ok(opened) => Ok(opened.as_slice().to_vec()),
        Err(ReadError::Format(error)) => Err(error),
        Err(other) => panic!("a data blob gave {other:?}, which is not a format error"),
    }
}

/// Opens `data` as a data blob, then as a sealed inner plaintext, then seals it as a chunk.
///
/// # Panics
///
/// If arbitrary bytes open or fail with anything but `Truncated`, `ZeroValue` or `Decrypt` at
/// the right lengths, `plain_len` over 1 MiB is not refused first, a sealed inner plaintext
/// gives another result than its stages give alone (the payload against `plain_len` before
/// the blob ID among them), or a written chunk does not open to itself or opens with a byte
/// flipped.
pub fn data_blob_open(data: &[u8]) {
    let context = BlobContext::new(
        VaultId::try_from_bytes([1; 16]).expect("non-zero ID"),
        ObjectId::try_from_bytes([2; 16]).expect("non-zero ID"),
        DekId::try_from_bytes([3; 16]).expect("non-zero ID"),
    );
    let dek = KdfKey::from_bytes([7; 32]).expect("non-zero key");
    let keys = ChunkKeys::derive(&dek, &[9; 32], context).expect("derives");
    let keyed = (ObjectClass::Ordinary, 2);
    let secret = (ObjectClass::Secret, 1);

    // Arbitrary bytes as a sealed blob.
    let entry = ChunkEntry::new(id(OTHER_ID), 100);
    for kind in [keyed, secret] {
        match open(&keys, kind, &entry, data) {
            Ok(_) => panic!("random bytes opened as a data blob"),
            Err(FormatError::Truncated) => assert!(data.len() < OVERHEAD, "Truncated too long"),
            Err(FormatError::ZeroValue) => assert_eq!(data[..NONCE_LEN], [0; NONCE_LEN]),
            Err(FormatError::Decrypt) => assert!(data.len() >= OVERHEAD, "Decrypt too short"),
            Err(other) => panic!("random bytes gave {other:?} instead of failing to decrypt"),
        }
    }
    let over_cap = ChunkEntry::new(id(OTHER_ID), MAX_PLAIN_LEN + 1);
    assert_eq!(
        open(&keys, keyed, &over_cap, data),
        Err(FormatError::Decompress),
        "plain_len over 1 MiB must be refused before anything else"
    );

    sealed_inner(&keys, data);
    round_trip(&keys, data);
}

/// `data` as an inner plaintext sealed under its blob's own key and AAD: the result must be
/// what the inner-plaintext check, the class rule, the decompressor and the blob-ID check say
/// on their own (FS-93 order).
fn sealed_inner(keys: &ChunkKeys, data: &[u8]) {
    let seal = |blob_id: &BlobId| {
        let aad = data_blob_aad(keys.context(), blob_id);
        cx_aead::seal_with_nonce(keys.chunk_key(), &aad, data, &NONCE)
    };
    let view = match inner::decode_inner(data) {
        Ok(view) => view,
        Err(error) => {
            let sealed = seal(&id(OTHER_ID));
            let entry = ChunkEntry::new(id(OTHER_ID), 0);
            for kind in [(ObjectClass::Ordinary, 2), (ObjectClass::Secret, 1)] {
                assert_eq!(open(keys, kind, &entry, &sealed), Err(error));
            }
            return;
        }
    };
    // What the chunk is, and the plain_len that names it, by the stage that makes it.
    let (plain, plain_len) = match view.comp() {
        Comp::Raw => (Ok(view.payload().to_vec()), view.payload().len() as u64),
        Comp::Zstd => {
            let frame = view.payload();
            let declared = zstd_safe::get_frame_content_size(frame)
                .ok()
                .flatten()
                .filter(|size| *size <= MAX_PLAIN_LEN)
                .unwrap_or(0);
            let decoded = DECOMPRESSOR.with_borrow_mut(|decompressor| {
                decompressor
                    .decode(frame, declared)
                    .map(|plain| plain.as_slice().to_vec())
            });
            let decoded = decoded.map_err(|error| match error {
                ReadError::Format(error) => error,
                other => panic!("decompression gave {other:?}"),
            });
            (decoded, declared)
        }
        other => panic!("decode_inner gave an unknown {other:?}"),
    };

    // A secret object never has comp = 1 (FS-53).
    let random = ChunkEntry::new(id(OTHER_ID), plain_len);
    let as_secret = open(
        keys,
        (ObjectClass::Secret, 1),
        &random,
        &seal(&id(OTHER_ID)),
    );
    let secret_expected = if view.comp() == Comp::Raw {
        plain.clone()
    } else {
        Err(FormatError::Padding)
    };
    assert_eq!(as_secret, secret_expected, "a secret object's chunk");

    // An ordinary object of two chunks, with the right keyed ID and a wrong one.
    let keyed = (ObjectClass::Ordinary, 2);
    match &plain {
        Ok(chunk) => {
            let right = id(*mac::mac(keys.blob_id_key(), chunk).as_bytes());
            let entry = ChunkEntry::new(right, plain_len);
            assert_eq!(open(keys, keyed, &entry, &seal(&right)), Ok(chunk.clone()));
            let wrong = ChunkEntry::new(id(OTHER_ID), plain_len);
            assert_eq!(
                open(keys, keyed, &wrong, &seal(&id(OTHER_ID))),
                Err(FormatError::Binding),
                "a chunk that does not MAC to its blob ID"
            );
            let longer = ChunkEntry::new(right, plain_len + 1);
            assert_eq!(
                open(keys, keyed, &longer, &seal(&right)),
                Err(FormatError::Decompress),
                "a chunk shorter than plain_len"
            );
            let longer_wrong = ChunkEntry::new(id(OTHER_ID), plain_len + 1);
            assert_eq!(
                open(keys, keyed, &longer_wrong, &seal(&id(OTHER_ID))),
                Err(FormatError::Decompress),
                "the payload's length is checked before the blob ID"
            );
        }
        Err(error) => {
            let entry = ChunkEntry::new(id(OTHER_ID), plain_len);
            let result = open(keys, keyed, &entry, &seal(&id(OTHER_ID)));
            assert_eq!(
                result,
                Err(*error),
                "the frame's own error comes before the blob ID"
            );
        }
    }
}

/// `data` written as a chunk of an ordinary and of a secret object opens to itself, and not
/// with a byte flipped.
fn round_trip(keys: &ChunkKeys, data: &[u8]) {
    let chunk = &data[..data.len().min(MAX_CHUNK)];
    for (class, count) in [
        (ObjectClass::Ordinary, 2),
        (ObjectClass::Ordinary, 1),
        (ObjectClass::Secret, 3),
    ] {
        let writer = ObjectSealer::new(keys, shape_of(class, count));
        let sealed = COMPRESSOR
            .with_borrow_mut(|compressor| writer.seal(compressor, chunk))
            .expect("seals");
        let opened = open(keys, (class, count), sealed.entry(), sealed.sealed());
        assert_eq!(
            opened.as_deref(),
            Ok(chunk),
            "a written chunk opens to itself"
        );

        let (Some(&high), Some(&low)) = (data.first(), data.get(1)) else {
            continue;
        };
        let mut tampered = sealed.sealed().to_vec();
        let index = usize::from(u16::from_be_bytes([high, low])) % tampered.len();
        tampered[index] ^= 0x01;
        assert_eq!(
            open(keys, (class, count), sealed.entry(), &tampered),
            Err(FormatError::Decrypt),
            "byte {index} flipped"
        );
    }
}
