//! TV-01: Project Wycheproof vectors for XChaCha20-Poly1305, HKDF-SHA-256 and Ed25519.
//!
//! The AEAD and HKDF cases run against the audited crates this crate wraps; the Ed25519 cases
//! run through [`VerifyingKey`], so they also test the strict rules of FS-14.

#[allow(dead_code, reason = "each runner uses part of the shared helpers")]
mod common;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use crypthix_crypto::sign::{Signature, VerifyingKey};
use crypthix_types::format_error::FormatError;
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct File<G> {
    number_of_tests: usize,
    test_groups: Vec<G>,
}

#[derive(Deserialize)]
struct AeadGroup {
    tests: Vec<AeadTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AeadTest {
    tc_id: u32,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
}

#[derive(Deserialize)]
struct HkdfGroup {
    tests: Vec<HkdfTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfTest {
    tc_id: u32,
    ikm: String,
    salt: String,
    info: String,
    size: usize,
    okm: String,
    result: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EddsaGroup {
    public_key: EddsaKey,
    tests: Vec<EddsaTest>,
}

#[derive(Deserialize)]
struct EddsaKey {
    pk: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EddsaTest {
    tc_id: u32,
    msg: String,
    sig: String,
    result: String,
    flags: Vec<String>,
}

/// `valid` must pass and `invalid` must fail; these files use no `acceptable` results.
fn expect_valid(result: &str, tc_id: u32) -> bool {
    match result {
        "valid" => true,
        "invalid" => false,
        other => panic!("tcId {tc_id}: unexpected result {other}"),
    }
}

#[test]
fn xchacha20_poly1305() {
    let file: File<AeadGroup> = common::load("external/wycheproof/xchacha20_poly1305_test.json");
    let mut ran = 0;
    for test in file.test_groups.iter().flat_map(|group| &group.tests) {
        ran += 1;
        let valid = expect_valid(&test.result, test.tc_id);
        let iv = common::hex(&test.iv);
        let Ok(nonce) = <[u8; 24]>::try_from(iv.as_slice()) else {
            assert!(
                !valid,
                "tcId {}: a valid case with a {}-byte nonce",
                test.tc_id,
                iv.len()
            );
            continue;
        };
        let cipher = XChaCha20Poly1305::new(&common::hex_array::<32>(&test.key).into());
        let nonce = XNonce::from(nonce);
        let aad = common::hex(&test.aad);
        let mut buffer = common::hex(&test.msg);
        let tag = cipher
            .encrypt_inout_detached(&nonce, &aad, buffer.as_mut_slice().into())
            .expect("encrypts");
        let matches =
            buffer == common::hex(&test.ct) && tag.as_slice() == common::hex(&test.tag).as_slice();
        assert_eq!(matches, valid, "tcId {}: encryption", test.tc_id);

        let mut buffer = common::hex(&test.ct);
        let opened = <[u8; 16]>::try_from(common::hex(&test.tag).as_slice()).is_ok_and(|tag| {
            cipher
                .decrypt_inout_detached(&nonce, &aad, buffer.as_mut_slice().into(), &Tag::from(tag))
                .is_ok()
        });
        assert_eq!(opened, valid, "tcId {}: decryption", test.tc_id);
        if valid {
            assert_eq!(
                buffer,
                common::hex(&test.msg),
                "tcId {}: plaintext",
                test.tc_id
            );
        }
    }
    assert_eq!(ran, file.number_of_tests);
    assert_eq!(ran, 315, "xchacha20_poly1305_test.json holds 315 cases");
}

#[test]
fn hkdf_sha256() {
    let file: File<HkdfGroup> = common::load("external/wycheproof/hkdf_sha256_test.json");
    let mut ran = 0;
    for test in file.test_groups.iter().flat_map(|group| &group.tests) {
        ran += 1;
        let valid = expect_valid(&test.result, test.tc_id);
        let hkdf = Hkdf::<Sha256>::new(Some(&common::hex(&test.salt)), &common::hex(&test.ikm));
        let mut okm = vec![0u8; test.size];
        let derived = hkdf.expand(&common::hex(&test.info), &mut okm).is_ok();
        assert_eq!(
            derived && okm == common::hex(&test.okm),
            valid,
            "tcId {}",
            test.tc_id
        );
    }
    assert_eq!(ran, file.number_of_tests);
    assert_eq!(ran, 86, "hkdf_sha256_test.json holds 86 cases");
}

/// The result FS-14 requires. A public key outside the prime-order subgroup is never accepted
/// (`WeakKey`), whether Wycheproof calls the case `invalid` or leaves it to the implementation
/// (`acceptable`); every other `invalid` case fails its signature check, and `valid` verifies.
fn ed25519_expected(test: &EddsaTest) -> Result<(), FormatError> {
    let weak_key = test
        .flags
        .iter()
        .any(|flag| flag == "SmallOrderPublicKey" || flag == "MixedOrderPublicKey");
    match (test.result.as_str(), weak_key) {
        ("valid", false) => Ok(()),
        ("invalid" | "acceptable", true) => Err(FormatError::WeakKey),
        ("invalid", false) => Err(FormatError::Signature),
        (result, _) => panic!("tcId {}: {result} with flags {:?}", test.tc_id, test.flags),
    }
}

#[test]
fn ed25519_through_the_strict_verifier() {
    let file: File<EddsaGroup> = common::load("external/wycheproof/ed25519_test.json");
    let mut ran = 0;
    for group in &file.test_groups {
        let key = VerifyingKey::from_bytes(&common::hex_array(&group.public_key.pk));
        for test in &group.tests {
            ran += 1;
            let result = key.and_then(|key| {
                let signature = <[u8; 64]>::try_from(common::hex(&test.sig).as_slice())
                    .map_err(|_| FormatError::Signature)?;
                key.verify_raw(&common::hex(&test.msg), &Signature::from_bytes(signature))
            });
            assert_eq!(result, ed25519_expected(test), "tcId {}", test.tc_id);
        }
    }
    assert_eq!(ran, file.number_of_tests);
    assert_eq!(ran, 210, "ed25519_test.json holds 210 cases");
}
