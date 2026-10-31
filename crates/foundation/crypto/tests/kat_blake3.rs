//! TV-01: the official BLAKE3 vectors, for plain, keyed and `derive_key` hashing with extended
//! output, plus the keyed XOF of [`mac::xof`] (FS-52).

#[allow(dead_code, reason = "each runner uses part of the shared helpers")]
mod common;

use crypthix_crypto::key::XofKey;
use crypthix_crypto::mac;
use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    key: String,
    context_string: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    input_len: usize,
    hash: String,
    keyed_hash: String,
    derive_key: String,
}

fn input(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("below 251"))
        .collect()
}

fn xof(mut hasher: blake3::Hasher, data: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    hasher.update(data).finalize_xof().fill(&mut out);
    out
}

#[test]
fn official_vectors() {
    let file: File = common::load("external/blake3/test_vectors.json");
    let key: [u8; 32] = file.key.as_bytes().try_into().expect("a 32-byte key");
    for case in &file.cases {
        let data = input(case.input_len);
        let expected = common::hex(&case.hash);
        assert_eq!(xof(blake3::Hasher::new(), &data, expected.len()), expected);
        assert_eq!(&expected[..32], blake3::hash(&data).as_bytes());
        let expected = common::hex(&case.keyed_hash);
        assert_eq!(
            xof(blake3::Hasher::new_keyed(&key), &data, expected.len()),
            expected
        );
        let expected = common::hex(&case.derive_key);
        let hasher = blake3::Hasher::new_derive_key(&file.context_string);
        assert_eq!(
            xof(hasher, &data, expected.len()),
            expected,
            "len {}",
            case.input_len
        );
    }
    assert_eq!(file.cases.len(), 35);
}

#[test]
fn gear_xof_is_the_keyed_xof_of_the_empty_input() {
    let file: File = common::load("external/blake3/test_vectors.json");
    let key: [u8; 32] = file.key.as_bytes().try_into().expect("a 32-byte key");
    let empty = file
        .cases
        .iter()
        .find(|case| case.input_len == 0)
        .expect("a 0-byte case");
    let expected = common::hex(&empty.keyed_hash);
    let mut out = vec![0u8; expected.len()];
    mac::xof(&XofKey::from_bytes(key).expect("non-zero"), &mut out);
    assert_eq!(out, expected);
}
