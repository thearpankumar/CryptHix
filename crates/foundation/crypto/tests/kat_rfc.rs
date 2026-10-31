//! TV-01: the RFC and draft vectors transcribed under `external/` (format spec 20.1).

#[allow(dead_code, reason = "each runner uses part of the shared helpers")]
mod common;

use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{R20, XChaCha20};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce};
use crypthix_crypto::sign::{Signature, VerifyingKey};
use crypthix_types::format_error::FormatError;
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::Sha256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct File<T> {
    number_of_tests: usize,
    tests: Vec<T>,
}

/// The cases of a transcribed file, which must hold exactly `count` of them (the number its
/// SOURCE sections contain).
fn tests<T: DeserializeOwned>(path: &str, count: usize) -> Vec<T> {
    let file: File<T> = common::load(path);
    assert_eq!(file.number_of_tests, count, "{path}: numberOfTests");
    assert_eq!(file.tests.len(), count, "{path}: cases");
    file.tests
}

#[derive(Deserialize)]
struct Aead {
    key: String,
    nonce: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
}

fn check_aead<C: AeadInOut>(cipher: &C, nonce: &chacha20poly1305::aead::Nonce<C>, test: &Aead) {
    let mut buffer = common::hex(&test.msg);
    let tag = cipher
        .encrypt_inout_detached(nonce, &common::hex(&test.aad), buffer.as_mut_slice().into())
        .expect("encrypts");
    assert_eq!(buffer, common::hex(&test.ct));
    assert_eq!(tag.as_slice(), common::hex(&test.tag).as_slice());
    cipher
        .decrypt_inout_detached(
            nonce,
            &common::hex(&test.aad),
            buffer.as_mut_slice().into(),
            &tag,
        )
        .expect("decrypts");
    assert_eq!(buffer, common::hex(&test.msg));
    let mut forged = tag.clone();
    forged[0] ^= 1;
    assert!(
        cipher
            .decrypt_inout_detached(
                nonce,
                &common::hex(&test.aad),
                common::hex(&test.ct).as_mut_slice().into(),
                &forged
            )
            .is_err(),
        "a forged tag decrypted"
    );
}

#[test]
fn rfc8439_chacha20_poly1305() {
    for test in tests::<Aead>("external/rfc8439/aead.json", 2) {
        let cipher = ChaCha20Poly1305::new(&common::hex_array::<32>(&test.key).into());
        check_aead(
            &cipher,
            &Nonce::from(common::hex_array::<12>(&test.nonce)),
            &test,
        );
    }
}

#[test]
fn xchacha_draft_aead() {
    for test in tests::<Aead>("external/xchacha-draft/aead.json", 1) {
        let cipher = XChaCha20Poly1305::new(&common::hex_array::<32>(&test.key).into());
        check_aead(
            &cipher,
            &XNonce::from(common::hex_array::<24>(&test.nonce)),
            &test,
        );
    }
}

#[derive(Deserialize)]
struct HChaCha {
    key: String,
    nonce: String,
    subkey: String,
}

#[test]
fn xchacha_draft_hchacha20() {
    for test in tests::<HChaCha>("external/xchacha-draft/hchacha.json", 1) {
        let subkey = chacha20::hchacha::<R20>(
            &common::hex_array::<32>(&test.key).into(),
            &common::hex_array::<16>(&test.nonce).into(),
        );
        assert_eq!(subkey.as_slice(), common::hex(&test.subkey).as_slice());
    }
}

#[derive(Deserialize)]
struct Stream {
    counter: u64,
    key: String,
    nonce: String,
    msg: String,
    keystream: String,
    ct: String,
}

#[test]
fn xchacha_draft_xchacha20() {
    for test in tests::<Stream>("external/xchacha-draft/stream.json", 2) {
        let mut cipher = XChaCha20::new(
            &common::hex_array::<32>(&test.key).into(),
            &common::hex_array::<24>(&test.nonce).into(),
        );
        cipher.seek(test.counter * 64);
        let mut keystream = vec![0u8; common::hex(&test.keystream).len()];
        cipher.apply_keystream(&mut keystream);
        assert_eq!(
            keystream,
            common::hex(&test.keystream),
            "counter {}",
            test.counter
        );
        let ct: Vec<u8> = common::hex(&test.msg)
            .iter()
            .zip(&keystream)
            .map(|(m, k)| m ^ k)
            .collect();
        assert_eq!(ct, common::hex(&test.ct), "counter {}", test.counter);
    }
}

#[derive(Deserialize)]
struct Hkdf5869 {
    ikm: String,
    salt: String,
    info: String,
    size: usize,
    prk: String,
    okm: String,
}

#[test]
fn rfc5869_hkdf_sha256() {
    for test in tests::<Hkdf5869>("external/rfc5869/hkdf_sha256.json", 3) {
        let salt = common::hex(&test.salt);
        let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), &common::hex(&test.ikm));
        assert_eq!(prk.as_slice(), common::hex(&test.prk).as_slice());
        let mut okm = vec![0u8; test.size];
        hkdf.expand(&common::hex(&test.info), &mut okm)
            .expect("valid length");
        assert_eq!(okm, common::hex(&test.okm));
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Argon {
    version: u32,
    memory_ki_b: u32,
    passes: u32,
    lanes: u32,
    password: String,
    salt: String,
    secret: String,
    ad: String,
    tag: String,
}

#[test]
/// Runs the `argon2` crate itself: the RFC case needs a secret and associated data, which the
/// passphrase wrapper never uses. `argon2id::derive` is checked against this same crate with
/// distinct parameters in its unit tests; no second Argon2id implementation is vendored.
fn rfc9106_argon2id() {
    for test in tests::<Argon>("external/rfc9106/argon2id.json", 1) {
        assert_eq!(test.version, 0x13);
        let params = ParamsBuilder::new()
            .m_cost(test.memory_ki_b)
            .t_cost(test.passes)
            .p_cost(test.lanes)
            .data(AssociatedData::new(&common::hex(&test.ad)).expect("short"))
            .output_len(32)
            .build()
            .expect("valid parameters");
        let secret = common::hex(&test.secret);
        let mut blocks = vec![Block::default(); params.block_count()];
        let argon2 = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
            .expect("short secret");
        let mut tag = [0u8; 32];
        argon2
            .hash_password_into_with_memory(
                &common::hex(&test.password),
                &common::hex(&test.salt),
                &mut tag,
                blocks.as_mut_slice(),
            )
            .expect("hashes");
        assert_eq!(tag.as_slice(), common::hex(&test.tag).as_slice());
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed25519 {
    name: String,
    secret_key: String,
    public_key: String,
    msg: String,
    sig: String,
}

#[test]
fn rfc8032_ed25519() {
    for test in tests::<Ed25519>("external/rfc8032/ed25519.json", 5) {
        let signer = ed25519_dalek::SigningKey::from_bytes(&common::hex_array(&test.secret_key));
        assert_eq!(
            signer.verifying_key().as_bytes(),
            &common::hex_array::<32>(&test.public_key)
        );
        let signature = signer.sign(&common::hex(&test.msg)).to_bytes();
        assert_eq!(
            signature,
            common::hex_array::<64>(&test.sig),
            "{}",
            test.name
        );
        let key =
            VerifyingKey::from_bytes(&common::hex_array(&test.public_key)).expect("valid key");
        key.verify_raw(&common::hex(&test.msg), &Signature::from_bytes(signature))
            .expect("verifies");
        let mut message = common::hex(&test.msg);
        message.push(0);
        let changed = key.verify_raw(&message, &Signature::from_bytes(signature));
        assert_eq!(
            changed,
            Err(FormatError::Signature),
            "{}: a changed message",
            test.name
        );
    }
}
