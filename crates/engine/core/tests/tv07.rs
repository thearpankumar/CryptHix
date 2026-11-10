//! Runs TV-07: chunk boundaries, Padmé, inner plaintexts, compression, decompression, and data
//! and meta blobs (FS-52 to FS-57).
//!
//! The encoder groups (`Compress`, `DataBlobSeal`) expect zstd's exact output, which is only
//! known for the version in the set's header, so they fail outright under any other version.
//! Every other group, decompression included, must pass with any zstd.

#[allow(dead_code, reason = "each runner uses part of the shared helpers")]
mod common;

use crypthix_core::blob::{
    self, BlobContext, BlobIdKind, ChunkEntry, ChunkKeys, MetaContext, MetaKey, MetaKind,
    ObjectClass, ObjectOpener, ObjectSealer,
};
use crypthix_core::chunk::{self, Chunks, GearTable, ObjectShape, StreamChunker};
use crypthix_core::compress::{Compressor, Decompressor};
use crypthix_core::error::ReadError;
use crypthix_core::inner::{self, Comp};
use crypthix_core::limits::{MAX_CHUNK, MIN_CHUNK};
use crypthix_core::pad;
use crypthix_crypto::cx_aead;
use crypthix_crypto::hash;
use crypthix_crypto::key::{KdfKey, XofKey};
use crypthix_crypto::label::HashLabel;
use crypthix_crypto::mac;
use crypthix_types::id::{BlobId, DekId, Epoch, ObjectId, VaultId};
use serde_json::Value;

use common::VectorSet;

const FILE: &str = "crypthix/v0/tv-07-chunk-blob.json";

/// The groups of TV-07 and their sizes.
const GROUPS: [(&str, usize); 8] = [
    ("Chunking", 21),
    ("Padme", 12),
    ("InnerDecode", 20),
    ("Compress", 9),
    ("Decompress", 32),
    ("DataBlobSeal", 4),
    ("DataBlobOpen", 29),
    ("MetaBlob", 13),
];

/// The groups whose expected bytes come from the zstd encoder.
const ENCODER_GROUPS: [&str; 2] = ["Compress", "DataBlobSeal"];

/// Every `expect` the data-blob open matrix must use at least once (format spec 20.4).
const OPEN_RESULTS: [&str; 8] = [
    "Ok",
    "Decrypt",
    "Binding",
    "Padding",
    "Limit",
    "Decompress",
    "Truncated",
    "ZeroValue",
];

fn comment(test: &Value) -> &str {
    test["comment"].as_str().expect("comment")
}

fn expect(test: &Value) -> &str {
    test["expect"].as_str().expect("expect")
}

fn usize_of(value: u64) -> usize {
    usize::try_from(value).expect("fits")
}

/// The first `len` bytes of the keyed XOF under `key` (the `dataKey` inputs).
fn xof(key: [u8; 32], len: usize) -> Vec<u8> {
    let key = XofKey::from_bytes(key).expect("non-zero key");
    let mut out = vec![0u8; len];
    mac::xof(&key, &mut out);
    out
}

/// A test's data: `chunk` as hex, `dataKey` and `length` as a stream, `pattern` repeated to
/// `length`, or `zeros`.
fn data(test: &Value) -> Vec<u8> {
    if common::has_input(test, "chunk") {
        common::input(test, "chunk")
    } else if common::has_input(test, "pattern") {
        let len = usize_of(common::int(test, "length"));
        common::input(test, "pattern")
            .into_iter()
            .cycle()
            .take(len)
            .collect()
    } else if common::has_input(test, "dataKey") {
        let len = usize_of(common::int(test, "length"));
        xof(common::input_array(test, "dataKey"), len)
    } else {
        vec![0; usize_of(common::int(test, "zeros"))]
    }
}

fn class(test: &Value) -> ObjectClass {
    match common::text(test, "class") {
        "ordinary" => ObjectClass::Ordinary,
        "secret" => ObjectClass::Secret,
        other => panic!("unknown class {other}"),
    }
}

fn kdf_key(test: &Value, name: &str) -> KdfKey {
    KdfKey::from_bytes(common::input_array(test, name)).expect("non-zero key")
}

fn vault_id(test: &Value) -> VaultId {
    VaultId::try_from_bytes(common::input_array(test, "vaultId")).expect("non-zero ID")
}

fn blob_id(bytes: [u8; 32]) -> BlobId {
    BlobId::try_from_bytes(bytes).expect("non-zero ID")
}

/// The format error of a failed open; anything else is a bug in the runner's set-up.
fn error_name(error: ReadError) -> &'static str {
    match error {
        ReadError::Format(error) => error.name(),
        other => panic!("not a format error: {other:?}"),
    }
}

fn check_chunking(test: &Value) {
    let seed = kdf_key(test, "chunkerSeed");
    let gear = GearTable::derive(&seed, &vault_id(test)).expect("derives");
    let class = class(test);
    let data = data(test);
    let expected: Vec<usize> = common::output_ints(test, "lengths")
        .into_iter()
        .map(usize_of)
        .collect();
    let chunks = Chunks::new(&gear, class, &data);
    let shape = chunks.object_shape();
    assert_eq!(shape.class(), class, "{}: the shape's class", comment(test));
    assert_eq!(
        shape.is_single(),
        expected.len() <= 1,
        "{}: the shape",
        comment(test)
    );
    // Every chunk but the last is at least the minimum (the maximum for the secret class), so
    // a chunker that gives more is not advancing: fail rather than loop on.
    let least = match class {
        ObjectClass::Ordinary => MIN_CHUNK,
        ObjectClass::Secret => MAX_CHUNK,
        other => panic!("no chunk bound for {other:?}"),
    };
    let most = data.len() / least + 1;
    let mut lengths = Vec::new();
    for range in chunks {
        assert!(
            lengths.len() < most && !range.is_empty(),
            "{}: chunk {range:?} after {} chunks, at most {most} expected",
            comment(test),
            lengths.len()
        );
        lengths.push(range.len());
    }
    assert_eq!(lengths, expected, "{}: in memory", comment(test));
    if class == ObjectClass::Ordinary {
        assert_eq!(
            chunk::cut(&gear, &data),
            expected.first().copied().unwrap_or(0),
            "{}: the first cut",
            comment(test)
        );
    }

    let mut chunker = StreamChunker::new(&gear, class, data.as_slice()).expect("a window");
    let mut streamed = Vec::new();
    while let Some(chunk) = chunker.next_chunk().expect("reads") {
        assert!(
            streamed.len() < most && !chunk.bytes().is_empty(),
            "{}: streamed chunk {} of {} bytes, at most {most} expected",
            comment(test),
            streamed.len(),
            chunk.bytes().len()
        );
        assert_eq!(chunk.index(), streamed.len() as u64, "{}", comment(test));
        assert_eq!(
            chunk.is_last(),
            streamed.len() + 1 == expected.len(),
            "{}: is_last",
            comment(test)
        );
        streamed.push(chunk.bytes().len());
    }
    assert_eq!(streamed, expected, "{}: streamed", comment(test));
}

fn check_padme(test: &Value) {
    let padded = pad::padme(common::int(test, "length"));
    assert_eq!(
        padded,
        Some(common::output_int(test, "padded")),
        "{}",
        comment(test)
    );
}

/// The inner plaintext of a test: `inner` as hex, or `header`, a payload stream and a zero pad.
fn inner_bytes(test: &Value) -> Vec<u8> {
    if common::has_input(test, "inner") {
        return common::input(test, "inner");
    }
    let payload = xof(
        common::input_array(test, "dataKey"),
        usize_of(common::int(test, "length")),
    );
    let pad = vec![0u8; usize_of(common::int(test, "padLength"))];
    [common::input(test, "header"), payload, pad].concat()
}

fn check_inner(test: &Value) {
    let bytes = inner_bytes(test);
    match inner::decode_inner(&bytes) {
        Ok(view) => {
            assert_eq!(expect(test), "Ok", "{}", comment(test));
            assert_eq!(
                u64::from(view.comp().code()),
                common::output_int(test, "comp"),
                "{}",
                comment(test)
            );
            let payload = if test.get("payload").is_some() {
                common::output(test, "payload")
            } else {
                xof(
                    common::input_array(test, "dataKey"),
                    usize_of(common::int(test, "length")),
                )
            };
            assert_eq!(view.payload(), payload, "{}", comment(test));
        }
        Err(error) => assert_eq!(error.name(), expect(test), "{}", comment(test)),
    }
}

fn check_compress(test: &Value, compressor: &mut Compressor) {
    let chunk = data(test);
    let inner = compressor
        .encode_chunk(&chunk, class(test))
        .expect("encodes");
    assert_eq!(
        u64::from(inner[0]),
        common::output_int(test, "comp"),
        "{}",
        comment(test)
    );
    assert_eq!(
        inner.len() as u64,
        common::output_int(test, "innerLength"),
        "{}",
        comment(test)
    );
    if test.get("inner").is_some() {
        assert_eq!(
            inner.as_slice(),
            common::output(test, "inner"),
            "{}",
            comment(test)
        );
    } else {
        // A raw inner plaintext given by its length only: the chunk, its header and zero pad.
        let view = inner::decode_inner(&inner).expect("well formed");
        assert_eq!(
            (view.comp(), view.payload()),
            (Comp::Raw, chunk.as_slice()),
            "{}",
            comment(test)
        );
    }
}

fn check_decompress(test: &Value, decompressor: &mut Decompressor) {
    let frame = if common::has_input(test, "frameZeros") {
        let zeros = vec![0; usize_of(common::int(test, "frameZeros"))];
        [
            common::input(test, "frameHead"),
            zeros,
            common::input(test, "frameTail"),
        ]
        .concat()
    } else {
        common::input(test, "frame")
    };
    let plain_len = common::int(test, "plainLen");
    match decompressor.decode(&frame, plain_len) {
        Ok(plain) => {
            assert_eq!(expect(test), "Ok", "{}", comment(test));
            let expected = if test.get("plaintextZeros").is_some() {
                vec![0; usize_of(common::output_int(test, "plaintextZeros"))]
            } else {
                common::output(test, "plaintext")
            };
            assert_eq!(plain.as_slice(), expected, "{}", comment(test));
        }
        Err(error) => assert_eq!(error_name(error), expect(test), "{}", comment(test)),
    }
}

/// The shape the chunker gives an object of `class` and `count` chunks, from a chunker run over
/// one byte or over zeros one byte longer than a maximum chunk; only the chunker makes shapes.
fn shape(class: ObjectClass, count: u64) -> ObjectShape {
    let seed = KdfKey::from_bytes([1; 32]).expect("non-zero key");
    let vault_id = VaultId::try_from_bytes([1; 16]).expect("non-zero ID");
    let gear = GearTable::derive(&seed, &vault_id).expect("derives");
    let len = if count == 1 { 1 } else { MAX_CHUNK + 1 };
    let shape = Chunks::new(&gear, class, &vec![0; len]).object_shape();
    assert_eq!(shape.is_single(), count == 1, "{count} chunks");
    assert_eq!(shape.class(), class);
    shape
}

/// The keys of a data-blob test, bound to its context.
fn chunk_keys(test: &Value) -> ChunkKeys {
    let context = BlobContext::new(
        vault_id(test),
        ObjectId::try_from_bytes(common::input_array(test, "objectId")).expect("non-zero ID"),
        DekId::try_from_bytes(common::input_array(test, "dekId")).expect("non-zero ID"),
    );
    ChunkKeys::derive(
        &kdf_key(test, "dek"),
        &common::input_array(test, "dekSalt"),
        context,
    )
    .expect("derives")
}

fn check_data_seal(test: &Value, compressor: &mut Compressor, decompressor: &mut Decompressor) {
    let keys = chunk_keys(test);
    let class = class(test);
    let count = common::int(test, "chunkCount");
    let chunk = common::input(test, "chunk");
    let expected_id: [u8; 32] = common::hex_array(test["blobId"].as_str().expect("blobId"));
    match BlobIdKind::for_object(class, count) {
        BlobIdKind::Keyed => {
            let keyed = mac::mac(keys.blob_id_key(), &chunk);
            assert_eq!(keyed.as_bytes(), &expected_id, "{}", comment(test));
        }
        BlobIdKind::Random => assert_eq!(
            common::input_array::<32>(test, "blobId"),
            expected_id,
            "{}: a random ID is given",
            comment(test)
        ),
        other => panic!("unknown blob ID kind {other:?}"),
    }
    let id = blob_id(expected_id);

    let inner = compressor.encode_chunk(&chunk, class).expect("encodes");
    assert_eq!(
        inner.as_slice(),
        common::output(test, "inner"),
        "{}",
        comment(test)
    );
    let aad = blob::data_blob_aad(keys.context(), &id);
    let a = hash::hash(HashLabel::CxAad, aad.as_bytes());
    let nonce = cx_aead::hedged_nonce(
        keys.chunk_key(),
        &a,
        &inner,
        &common::input_array(test, "rand"),
    );
    assert_eq!(
        nonce.as_slice(),
        common::output(test, "nonce"),
        "{}",
        comment(test)
    );
    let sealed = cx_aead::seal_with_nonce(keys.chunk_key(), &aad, &inner, &nonce);
    assert_eq!(sealed, common::output(test, "sealed"), "{}", comment(test));

    let entry = ChunkEntry::new(id, chunk.len() as u64);
    let reader = ObjectOpener::new(&keys, class, count);
    let opened = reader.open(decompressor, &entry, &sealed).expect("opens");
    assert_eq!(opened.as_slice(), chunk, "{}", comment(test));

    // The real writer, with its own randomness, gives a blob that opens the same way.
    let writer = ObjectSealer::new(&keys, shape(class, count));
    assert_eq!(
        writer.blob_id_kind(),
        reader.blob_id_kind(),
        "{}",
        comment(test)
    );
    let written = writer.seal(compressor, &chunk).expect("seals");
    if BlobIdKind::for_object(class, count) == BlobIdKind::Keyed {
        assert_eq!(written.blob_id(), &id, "{}", comment(test));
    }
    let opened = reader
        .open(decompressor, written.entry(), written.sealed())
        .expect("opens");
    assert_eq!(opened.as_slice(), chunk, "{}", comment(test));
}

/// Checks one data-blob open and returns its `expect`.
fn check_data_open<'a>(test: &'a Value, decompressor: &mut Decompressor) -> &'a str {
    let keys = chunk_keys(test);
    let entry = ChunkEntry::new(
        blob_id(common::input_array(test, "blobId")),
        common::int(test, "plainLen"),
    );
    let sealed = common::input(test, "sealed");
    let result = ObjectOpener::new(&keys, class(test), common::int(test, "chunkCount")).open(
        decompressor,
        &entry,
        &sealed,
    );
    match result {
        Ok(opened) => {
            assert_eq!(expect(test), "Ok", "{}", comment(test));
            assert_eq!(
                opened.as_slice(),
                common::output(test, "plaintext"),
                "{}",
                comment(test)
            );
        }
        Err(error) => assert_eq!(error_name(error), expect(test), "{}", comment(test)),
    }
    expect(test)
}

fn check_meta(test: &Value) {
    let kind_code = u8::try_from(common::int(test, "kind")).expect("a byte");
    let kind = MetaKind::from_code(kind_code).expect("a meta kind");
    let epoch = u32::try_from(common::int(test, "epoch")).expect("a u32");
    let context = MetaContext::new(
        vault_id(test),
        kind,
        Epoch::try_new(epoch).expect("non-zero"),
    );
    let key = MetaKey::derive(&kdf_key(test, "kek"), context).expect("derives");
    let id = blob_id(common::input_array(test, "blobId"));

    if !common::has_input(test, "cbor") {
        let sealed = common::input(test, "sealed");
        match blob::open_meta_blob(&key, &id, &sealed) {
            Ok(cbor) => {
                assert_eq!(expect(test), "Ok", "{}", comment(test));
                assert_eq!(
                    cbor.as_slice(),
                    common::output(test, "cbor"),
                    "{}",
                    comment(test)
                );
            }
            Err(error) => assert_eq!(error_name(error), expect(test), "{}", comment(test)),
        }
        return;
    }

    let cbor = common::input(test, "cbor");
    let aad = blob::meta_blob_aad(&context, &id);
    let a = hash::hash(HashLabel::CxAad, aad.as_bytes());
    let nonce = cx_aead::hedged_nonce(
        key.seal_key(),
        &a,
        &cbor,
        &common::input_array(test, "rand"),
    );
    assert_eq!(
        nonce.as_slice(),
        common::output(test, "nonce"),
        "{}",
        comment(test)
    );
    let sealed = cx_aead::seal_with_nonce(key.seal_key(), &aad, &cbor, &nonce);
    assert_eq!(sealed, common::output(test, "sealed"), "{}", comment(test));
    let opened = blob::open_meta_blob(&key, &id, &sealed).expect("opens");
    assert_eq!(opened.as_slice(), cbor, "{}", comment(test));

    let written = blob::seal_meta_blob(&key, &cbor).expect("seals");
    let opened = blob::open_meta_blob(&key, written.blob_id(), written.sealed()).expect("opens");
    assert_eq!(opened.as_slice(), cbor, "{}", comment(test));
}

/// Every group but the encoder's, which any zstd version must pass.
#[test]
#[cfg_attr(miri, ignore = "zstd is C, which Miri cannot run")]
fn tv07_chunk_blob() {
    let set = VectorSet::load_exact(FILE, &GROUPS);
    let mut decompressor = Decompressor::new();
    for group in &set.test_groups {
        let kind = group.kind.as_str();
        if ENCODER_GROUPS.contains(&kind) {
            continue;
        }
        let mut seen = Vec::new();
        for test in &group.tests {
            match kind {
                "Chunking" => check_chunking(test),
                "Padme" => check_padme(test),
                "InnerDecode" => check_inner(test),
                "Decompress" => check_decompress(test, &mut decompressor),
                "DataBlobOpen" => seen.push(check_data_open(test, &mut decompressor)),
                "MetaBlob" => check_meta(test),
                other => panic!("unknown group {other}"),
            }
        }
        if kind == "DataBlobOpen" {
            for result in OPEN_RESULTS {
                assert!(seen.contains(&result), "no open case expects {result}");
            }
        }
    }
}

/// The encoder groups: zstd must be the version the vectors were made with (FS-53).
#[test]
#[cfg_attr(miri, ignore = "zstd is C, which Miri cannot run")]
fn tv07_encoder_under_the_pinned_zstd() {
    let set = VectorSet::load_exact(FILE, &GROUPS);
    let header = set.zstd.as_deref().expect("TV-07 names its zstd version");
    assert_eq!(
        zstd_safe::version_string(),
        header,
        "the encoder groups only hold for the zstd version the vectors were made with"
    );
    let mut compressor = Compressor::new().expect("a context");
    let mut decompressor = Decompressor::new();
    for group in &set.test_groups {
        match group.kind.as_str() {
            "Compress" => {
                for test in &group.tests {
                    check_compress(test, &mut compressor);
                }
            }
            "DataBlobSeal" => {
                for test in &group.tests {
                    check_data_seal(test, &mut compressor, &mut decompressor);
                }
            }
            _ => {}
        }
    }
}
