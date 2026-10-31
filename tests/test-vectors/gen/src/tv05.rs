//! TV-05: CX-AEAD seal and open, commitment, and the hedged and synthetic nonces (FS-27 to
//! FS-29).
//!
//! Only this set expects `Commitment` and `AeadTag`; every other set expects `Decrypt` for a
//! CX-AEAD failure (FS-94).

use crypthix_crypto::test_rng::Stream;

use crate::cx;
use crate::labels;
use crate::test_case::{Input, TestCase};
use crate::vector_set::VectorSet;

/// The seed of the set's streams: `BLAKE3("crypthix-vector-gen TV-05")`.
fn seed() -> [u8; 32] {
    *blake3::hash(b"crypthix-vector-gen TV-05").as_bytes()
}

/// A blob-data AAD for `object_id`, `dek_id` and `blob_id` (FS-55).
fn blob_aad(stream: &mut Stream) -> Vec<u8> {
    let vault_id: [u8; 16] = stream.bytes();
    let object_id: [u8; 16] = stream.bytes();
    let dek_id: [u8; 16] = stream.bytes();
    let blob_id: [u8; 32] = stream.bytes();
    cx::aad(
        labels::full("aad", "blob-data"),
        &[&vault_id, &[0x01], &object_id, &dek_id, &blob_id],
    )
}

fn given_nonce_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    [
        ("an empty plaintext", 0),
        ("a one-byte plaintext", 1),
        ("a 100-byte plaintext", 100),
    ]
    .into_iter()
    .map(|(comment, len)| {
        let mut stream = Stream::new(seed, comment);
        let key: [u8; 32] = stream.bytes();
        let aad = blob_aad(&mut stream);
        let nonce: [u8; 24] = stream.bytes();
        let mut plaintext = vec![0u8; len];
        stream.fill_bytes(&mut plaintext);
        TestCase::new(
            comment,
            &["GivenNonce"],
            "Ok",
            vec![
                ("key", Input::bytes(&key)),
                ("aad", Input::bytes(&aad)),
                ("plaintext", Input::bytes(&plaintext)),
                ("nonce", Input::bytes(&nonce)),
            ],
        )
        .with_outputs(vec![(
            "sealed",
            Input::bytes(&cx::seal(&key, &aad, &plaintext, &nonce)),
        )])
    })
    .collect()
}

/// One hedged seal: its nonce from `rand`, then the seal under that nonce.
fn hedged_case(
    comment: &'static str,
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
    rand: &[u8; 32],
) -> TestCase {
    let nonce = cx::hedged_nonce(key, aad, plaintext, rand);
    TestCase::new(
        comment,
        &["HedgedNonce"],
        "Ok",
        vec![
            ("key", Input::bytes(key)),
            ("aad", Input::bytes(aad)),
            ("plaintext", Input::bytes(plaintext)),
            ("rand", Input::bytes(rand)),
        ],
    )
    .with_outputs(vec![
        ("nonce", Input::bytes(&nonce)),
        (
            "sealed",
            Input::bytes(&cx::seal(key, aad, plaintext, &nonce)),
        ),
    ])
}

/// Hedged nonces for a key wrap and for data blobs, including two blobs sealed with replayed
/// randomness, as after a VM restore without a VM generation ID (T-81): their nonces differ.
fn hedged_nonce_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "a 104-byte DEK wrap");
    let key: [u8; 32] = stream.bytes();
    let vault_id: [u8; 16] = stream.bytes();
    let object_id: [u8; 16] = stream.bytes();
    let dek_id: [u8; 16] = stream.bytes();
    let dek_salt: [u8; 32] = stream.bytes();
    let wrap_aad = cx::aad(
        labels::full("aad", "dek-wrap"),
        &[
            &vault_id,
            &object_id,
            &dek_id,
            &dek_salt,
            &3u32.to_be_bytes(),
        ],
    );
    let dek: [u8; 32] = stream.bytes();
    let wrap_rand: [u8; 32] = stream.bytes();

    let mut stream = Stream::new(seed, "data blobs with replayed randomness");
    let blob_key: [u8; 32] = stream.bytes();
    let blob_aad = blob_aad(&mut stream);
    let mut chunk = vec![0u8; 100];
    stream.fill_bytes(&mut chunk);
    let mut other_chunk = chunk.clone();
    other_chunk[99] ^= 1;
    let replayed: [u8; 32] = stream.bytes();
    vec![
        hedged_case("a 104-byte DEK wrap", &key, &wrap_aad, &dek, &wrap_rand),
        hedged_case(
            "a 100-byte data blob",
            &blob_key,
            &blob_aad,
            &chunk,
            &replayed,
        ),
        hedged_case(
            "another data blob sealed with the same, replayed randomness",
            &blob_key,
            &blob_aad,
            &other_chunk,
            &replayed,
        ),
    ]
}

fn synthetic_nonce_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "shard header");
    let key: [u8; 32] = stream.bytes();
    let nonce_key: [u8; 32] = stream.bytes();
    let preamble_context: [u8; 16] = stream.bytes();
    let vault_id: [u8; 16] = stream.bytes();
    let pack_id: [u8; 16] = stream.bytes();
    let mut aad = cx::prefix(labels::full("aad", "shard-header"));
    aad.extend_from_slice(&[preamble_context.as_slice(), &vault_id, &pack_id, &[0]].concat());
    let mut header = vec![0u8; 96];
    stream.fill_bytes(&mut header);
    let mut changed = header.clone();
    changed[95] ^= 1;
    [
        ("a 96-byte shard header", header),
        ("the same header with its last bit flipped", changed),
    ]
    .into_iter()
    .map(|(comment, plaintext)| {
        let nonce = cx::synthetic_nonce(&nonce_key, &aad, &plaintext);
        TestCase::new(
            comment,
            &["SyntheticNonce"],
            "Ok",
            vec![
                ("key", Input::bytes(&key)),
                ("nonceKey", Input::bytes(&nonce_key)),
                ("aad", Input::bytes(&aad)),
                ("plaintext", Input::bytes(&plaintext)),
            ],
        )
        .with_outputs(vec![
            ("nonce", Input::bytes(&nonce)),
            (
                "sealed",
                Input::bytes(&cx::seal(&key, &aad, &plaintext, &nonce)),
            ),
        ])
    })
    .collect()
}

/// One open test: `plaintext` is the expected output when the seal opens.
fn open_case(
    comment: &'static str,
    flag: &'static str,
    expect: &'static str,
    [key, aad, sealed]: [&[u8]; 3],
    plaintext: Option<&[u8]>,
) -> TestCase {
    let test = TestCase::new(
        comment,
        &[flag],
        expect,
        vec![
            ("key", Input::bytes(key)),
            ("aad", Input::bytes(aad)),
            ("sealed", Input::bytes(sealed)),
        ],
    );
    match plaintext {
        Some(plaintext) => test.with_outputs(vec![("plaintext", Input::bytes(plaintext))]),
        None => test,
    }
}

/// `sealed` with the byte at `index` flipped.
fn flip(sealed: &[u8], index: usize) -> Vec<u8> {
    let mut out = sealed.to_vec();
    out[index] ^= 0x80;
    out
}

/// The negative matrix of format spec 20.4 for CX-AEAD, with the boundaries of every region.
fn open_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "open");
    let key: [u8; 32] = stream.bytes();
    let other_key: [u8; 32] = stream.bytes();
    let aad = blob_aad(&mut stream);
    let label_len = cx::prefix(labels::full("aad", "blob-data")).len();
    let relabelled = [
        cx::prefix(labels::full("aad", "blob-meta")),
        aad[label_len..].to_vec(),
    ]
    .concat();
    let last_field = flip(&aad, aad.len() - 1);
    let suite_byte = flip(&aad, label_len + 3);
    let nonce: [u8; 24] = stream.bytes();
    let other_nonce: [u8; 24] = stream.bytes();
    let rand: [u8; 32] = stream.bytes();
    let mut plaintext = vec![0u8; 40];
    stream.fill_bytes(&mut plaintext);
    let sealed = cx::seal(&key, &aad, &plaintext, &nonce);
    let empty = cx::seal(&key, &aad, b"", &nonce);
    let hedged = cx::seal(
        &key,
        &aad,
        &plaintext,
        &cx::hedged_nonce(&key, &aad, &plaintext, &rand),
    );
    let other_nonce_seal = [&other_nonce[..], &sealed[24..]].concat();
    let shortened = [&sealed[..56], &sealed[57..]].concat();
    let zero_nonce = [&[0u8; 24][..], &sealed[24..]].concat();
    let tag = sealed.len() - 16;
    let ok = Some(plaintext.as_slice());

    #[rustfmt::skip]
    let tests = vec![
        open_case("the seal opens", "Opens", "Ok", [&key, &aad, &sealed], ok),
        open_case("an empty plaintext is exactly the 72-byte overhead", "Opens", "Ok", [&key, &aad, &empty], Some(b"")),
        open_case("a seal with a hedged nonce opens the same way", "Opens", "Ok", [&key, &aad, &hedged], ok),
        open_case("another key", "CommitmentCheck", "Commitment", [&other_key, &aad, &sealed], None),
        open_case("the last AAD field changed", "CommitmentCheck", "Commitment", [&key, &last_field, &sealed], None),
        open_case("the AAD label length byte changed", "CommitmentCheck", "Commitment", [&key, &flip(&aad, 0), &sealed], None),
        open_case("the AAD suite byte changed", "CommitmentCheck", "Commitment", [&key, &suite_byte, &sealed], None),
        open_case("the same AAD fields under another label", "CommitmentCheck", "Commitment", [&key, &relabelled, &sealed], None),
        open_case("the first nonce byte changed", "CommitmentCheck", "Commitment", [&key, &aad, &flip(&sealed, 0)], None),
        open_case("the last nonce byte changed", "CommitmentCheck", "Commitment", [&key, &aad, &flip(&sealed, 23)], None),
        open_case("the same commitment, ciphertext and tag under another nonce", "CommitmentCheck", "Commitment", [&key, &aad, &other_nonce_seal], None),
        open_case("the first commitment byte changed", "CommitmentCheck", "Commitment", [&key, &aad, &flip(&sealed, 24)], None),
        open_case("the last commitment byte changed", "CommitmentCheck", "Commitment", [&key, &aad, &flip(&sealed, 55)], None),
        open_case("the first ciphertext byte changed", "TagCheck", "AeadTag", [&key, &aad, &flip(&sealed, 56)], None),
        open_case("the first tag byte changed", "TagCheck", "AeadTag", [&key, &aad, &flip(&sealed, tag)], None),
        open_case("the last tag byte changed", "TagCheck", "AeadTag", [&key, &aad, &flip(&sealed, sealed.len() - 1)], None),
        open_case("one ciphertext byte removed", "TagCheck", "AeadTag", [&key, &aad, &shortened], None),
        open_case("an all-zero nonce", "ZeroNonce", "ZeroValue", [&key, &aad, &zero_nonce], None),
        open_case("71 bytes, one short of the overhead", "Short", "Truncated", [&key, &aad, &empty[..71]], None),
        open_case("no bytes", "Short", "Truncated", [&key, &aad, b""], None),
    ];
    tests
}

/// TV-05.
pub(crate) fn set() -> VectorSet {
    let seed = seed();
    VectorSet {
        file: "tv-05-cx-aead.json",
        set: "TV-05",
        structure: "cx-aead",
        seed: Some(seed),
        extra: vec![],
        notes: vec![
            (
                "GivenNonce",
                &["FS-27", "FS-29", "M-9", "T-38"],
                "Seal with a given nonce, the definition of FS-27: `nonce ‖ C ‖ ct ‖ tag`.",
            ),
            (
                "HedgedNonce",
                &["FS-29", "M-36", "T-81"],
                "Every nonce but a shard header's is `MAC(K_n, rand ‖ a ‖ pt)[..24]`; replayed randomness under another plaintext gives another nonce; a DEK wrap is 104 bytes.",
            ),
            (
                "SyntheticNonce",
                &["FS-29", "FS-62", "T-38"],
                "Shard headers use `MAC(K_shn, a ‖ pt)[..24]`; a different header gets a different nonce.",
            ),
            (
                "Opens",
                &["FS-27", "FS-28", "M-9"],
                "A valid seal opens to its plaintext.",
            ),
            (
                "CommitmentCheck",
                &["FS-27", "FS-28", "M-9", "T-36"],
                "A changed key, nonce, AAD or commitment fails the commitment, which is checked first.",
            ),
            (
                "TagCheck",
                &["FS-28", "M-9"],
                "A changed ciphertext or tag reaches the Poly1305 tag check.",
            ),
            (
                "ZeroNonce",
                &["FS-03", "FS-28", "T-37"],
                "An all-zero nonce is a zero value.",
            ),
            (
                "Short",
                &["FS-27", "FS-28", "M-9"],
                "Input shorter than the 72-byte overhead.",
            ),
        ],
        groups: vec![
            ("GivenNonce", given_nonce_tests(&seed)),
            ("HedgedNonce", hedged_nonce_tests(&seed)),
            ("SyntheticNonce", synthetic_nonce_tests(&seed)),
            ("Open", open_tests(&seed)),
        ],
    }
}
