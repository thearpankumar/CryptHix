//! Runs TV-05: CX-AEAD seal and open, the commitment check and the hedged and synthetic nonces.

#[allow(dead_code, reason = "each runner uses part of the shared helpers")]
mod common;

use crypthix_crypto::aad::Aad;
use crypthix_crypto::cx_aead;
use crypthix_crypto::hash;
use crypthix_crypto::key::{SealKey, ShardNonceKey};
use crypthix_crypto::label::HashLabel;
use crypthix_types::format_error::FormatError;
use serde_json::Value;

use common::VectorSet;

/// The groups of TV-05 and their sizes.
const GROUPS: [(&str, usize); 4] = [
    ("GivenNonce", 3),
    ("HedgedNonce", 3),
    ("SyntheticNonce", 2),
    ("Open", 20),
];

/// Every `expect` value the open matrix must use at least once (format spec 20.4).
const OPEN_RESULTS: [&str; 5] = ["Ok", "Commitment", "AeadTag", "Truncated", "ZeroValue"];

fn key(test: &Value) -> SealKey {
    SealKey::from_bytes(common::input_array(test, "key")).expect("non-zero key")
}

fn aad(test: &Value) -> Aad {
    Aad::from_bytes(common::input(test, "aad"))
}

fn check_seal(test: &Value, nonce: &[u8; 24]) {
    let plaintext = common::input(test, "plaintext");
    let sealed = cx_aead::seal_with_nonce(&key(test), &aad(test), &plaintext, nonce);
    assert_eq!(
        sealed,
        common::output(test, "sealed"),
        "{}",
        test["comment"]
    );
    let opened = cx_aead::open(&key(test), &aad(test), &sealed).expect("opens");
    assert_eq!(opened.as_slice(), plaintext, "{}", test["comment"]);
}

fn check_given(test: &Value) {
    check_seal(test, &common::input_array(test, "nonce"));
}

fn check_hedged(test: &Value) -> [u8; 24] {
    let a = hash::hash(HashLabel::CxAad, &common::input(test, "aad"));
    let rand = common::input_array(test, "rand");
    let nonce = cx_aead::hedged_nonce(&key(test), &a, &common::input(test, "plaintext"), &rand);
    assert_eq!(
        nonce.as_slice(),
        common::output(test, "nonce"),
        "{}",
        test["comment"]
    );
    check_seal(test, &nonce);
    nonce
}

fn check_synthetic(test: &Value) -> [u8; 24] {
    let a = hash::hash(HashLabel::CxAad, &common::input(test, "aad"));
    let nonce_key =
        ShardNonceKey::from_bytes(common::input_array(test, "nonceKey")).expect("non-zero key");
    let nonce = cx_aead::synthetic_nonce(&nonce_key, &a, &common::input(test, "plaintext"));
    assert_eq!(
        nonce.as_slice(),
        common::output(test, "nonce"),
        "{}",
        test["comment"]
    );
    check_seal(test, &nonce);
    nonce
}

/// Checks one open case and returns its `expect`.
fn check_open(test: &Value) -> &str {
    let sealed = common::input(test, "sealed");
    let expect = test["expect"].as_str().expect("expect");
    match cx_aead::open_detailed(&key(test), &aad(test), &sealed) {
        Ok(plaintext) => {
            assert_eq!(expect, "Ok", "{}", test["comment"]);
            assert_eq!(
                plaintext.as_slice(),
                common::output(test, "plaintext"),
                "{}",
                test["comment"]
            );
        }
        Err(error) => assert_eq!(error.name(), expect, "{}", test["comment"]),
    }
    // Callers outside the crate see `Truncated`, `ZeroValue` or the opaque `Decrypt` (FS-28).
    let opaque = cx_aead::open(&key(test), &aad(test), &sealed).err();
    let expected = match expect {
        "Ok" => None,
        "Truncated" => Some(FormatError::Truncated),
        "ZeroValue" => Some(FormatError::ZeroValue),
        _ => Some(FormatError::Decrypt),
    };
    assert_eq!(opaque, expected, "{}", test["comment"]);
    expect
}

#[test]
fn tv05_cx_aead() {
    let set = VectorSet::load_exact("crypthix/v0/tv-05-cx-aead.json", &GROUPS);
    for group in &set.test_groups {
        match group.kind.as_str() {
            "GivenNonce" => {
                for test in &group.tests {
                    check_given(test);
                }
            }
            "HedgedNonce" => {
                // Two of the seals replay the same randomness (T-81); their nonces still differ.
                let nonces: Vec<[u8; 24]> = group.tests.iter().map(check_hedged).collect();
                assert!(
                    nonces.windows(2).all(|pair| pair[0] != pair[1]),
                    "hedged nonces collide"
                );
            }
            "SyntheticNonce" => {
                let nonces: Vec<[u8; 24]> = group.tests.iter().map(check_synthetic).collect();
                assert!(
                    nonces.windows(2).all(|pair| pair[0] != pair[1]),
                    "SIV nonces collide"
                );
            }
            "Open" => {
                let seen: Vec<&str> = group.tests.iter().map(check_open).collect();
                for result in OPEN_RESULTS {
                    assert!(seen.contains(&result), "no open case expects {result}");
                }
            }
            other => panic!("unknown group {other}"),
        }
    }
}
