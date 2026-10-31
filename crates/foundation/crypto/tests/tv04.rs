//! Runs TV-04: labels, `H`, `KDF`, `MAC`, the derived keys of FS-38 and zero values.

#[allow(dead_code, reason = "each runner uses part of the shared helpers")]
mod common;

use crypthix_crypto::hash::{self, Hash32};
use crypthix_crypto::kdf::{self, KdfContext};
use crypthix_crypto::key::{KdfKey, MacKey, SealKey, ShardNonceKey, XofKey};
use crypthix_crypto::label::XofKeyLabel;
use crypthix_crypto::label::{AadLabel, CommitLabel, HashLabel, KdfKeyLabel, KdfLabel, SigLabel};
use crypthix_crypto::label::{DeriveLabel, MacKeyLabel, SealKeyLabel, ShardNonceKeyLabel};
use crypthix_crypto::mac;
use crypthix_types::format_error::FormatError;
use crypthix_types::id::{Epoch, ObjectId, RootSeq};
use serde_json::Value;

use common::VectorSet;

/// The groups of TV-04 and their sizes: 65 labels, 5 hashes, the 25 keys of FS-38, 3 MAC and
/// XOF cases and 7 zero-value cases.
const GROUPS: [(&str, usize); 5] = [
    ("LabelPrefix", 65),
    ("Hash", 5),
    ("DerivedKey", 25),
    ("Mac", 3),
    ("ZeroValue", 7),
];

fn hash_label(name: &str) -> HashLabel {
    *HashLabel::ALL
        .iter()
        .find(|label| label.as_str() == name)
        .unwrap_or_else(|| panic!("{name} is not a hash label"))
}

fn every_label() -> Vec<&'static str> {
    let kdf = KdfLabel::ALL.iter().map(|label| label.as_str());
    let aad = AadLabel::ALL.iter().map(|label| label.as_str());
    let sig = SigLabel::ALL.iter().map(|label| label.as_str());
    let hash = HashLabel::ALL.iter().map(|label| label.as_str());
    kdf.chain(aad).chain(sig).chain(hash).collect()
}

fn check_label_prefixes(tests: &[Value]) {
    let vector_labels: Vec<&str> = tests
        .iter()
        .map(|test| common::text(test, "label"))
        .collect();
    assert_eq!(
        vector_labels,
        every_label(),
        "the registry differs from TV-04"
    );
    for test in tests {
        let label = common::text(test, "label");
        let mut prefix = vec![u8::try_from(label.len()).expect("short")];
        prefix.extend_from_slice(label.as_bytes());
        assert_eq!(prefix, common::output(test, "prefix"), "{label}");
    }
}

fn check_hash(test: &Value) {
    let label = hash_label(common::text(test, "label"));
    let digest = hash::hash(label, &common::input(test, "data"));
    assert_eq!(
        digest.as_bytes().as_slice(),
        common::output(test, "hash"),
        "{}",
        test["comment"]
    );
}

/// Derives under the typed label whose name matches `label`, among the labels of `L`.
fn derive<L: DeriveLabel>(
    test: &Value,
    labels: &[L],
    bytes: impl Fn(&L::Output) -> [u8; 32],
) -> Option<[u8; 32]> {
    let name = common::text(test, "label");
    let label = *labels
        .iter()
        .find(|label| Into::<KdfLabel>::into(**label).as_str() == name)?;
    let ikm = KdfKey::from_bytes(common::input_array(test, "ikm")).expect("non-zero ikm");
    let salt: Option<[u8; 32]> = test["inputs"]["salt"].as_str().map(common::hex_array);
    let context = KdfContext::from_bytes(common::input(test, "context"));
    Some(bytes(&kdf::kdf(&ikm, salt.as_ref(), label, &context)))
}

fn check_derived_key(test: &Value) {
    let derived = match common::text(test, "keyType") {
        "SealKey" => derive(test, SealKeyLabel::ALL, SealKey::to_bytes),
        "MacKey" => derive(test, MacKeyLabel::ALL, MacKey::to_bytes),
        "ShardNonceKey" => derive(test, ShardNonceKeyLabel::ALL, ShardNonceKey::to_bytes),
        "KdfKey" => derive(test, KdfKeyLabel::ALL, KdfKey::to_bytes),
        "XofKey" => derive(test, XofKeyLabel::ALL, XofKey::to_bytes),
        "RootCommit" => derive(test, CommitLabel::ALL, |commit| *commit.as_bytes()),
        other => panic!("unknown key type {other}"),
    };
    let derived = derived.unwrap_or_else(|| panic!("{}: label of another type", test["comment"]));
    assert_eq!(
        derived.as_slice(),
        common::output(test, "key"),
        "{}",
        test["comment"]
    );
}

fn check_mac(test: &Value) {
    let key = common::input_array(test, "key");
    if test["xof"].is_string() {
        let expected = common::output(test, "xof");
        let mut out = vec![0u8; expected.len()];
        mac::xof(&XofKey::from_bytes(key).expect("non-zero"), &mut out);
        assert_eq!(out, expected, "{}", test["comment"]);
    } else {
        let key = MacKey::from_bytes(key).expect("non-zero");
        let tag = mac::mac(&key, &common::input(test, "data"));
        assert_eq!(
            tag.as_bytes().as_slice(),
            common::output(test, "mac"),
            "{}",
            test["comment"]
        );
    }
}

fn check_zero_value(test: &Value) {
    let value = &test["inputs"]["value"];
    let result: Result<(), FormatError> = match common::text(test, "kind") {
        "key" => KdfKey::from_bytes(common::input_array(test, "value")).map(drop),
        "objectId" => ObjectId::try_from_bytes(common::input_array(test, "value")).map(drop),
        "hash" => Hash32::try_from_bytes(common::input_array(test, "value")).map(drop),
        "epoch" => {
            Epoch::try_new(u32::try_from(value.as_u64().expect("int")).expect("u32")).map(drop)
        }
        "rootSeq" => RootSeq::try_new(value.as_u64().expect("int")).map(drop),
        other => panic!("unknown kind {other}"),
    };
    let name = result.map_or_else(FormatError::name, |()| "Ok");
    assert_eq!(name, test["expect"], "{}", test["comment"]);
}

#[test]
fn tv04_domain_separation() {
    let set = VectorSet::load_exact("crypthix/v0/tv-04-domain-separation.json", &GROUPS);
    for group in &set.test_groups {
        let check: fn(&Value) = match group.kind.as_str() {
            "LabelPrefix" => {
                check_label_prefixes(&group.tests);
                continue;
            }
            "Hash" => check_hash,
            "DerivedKey" => check_derived_key,
            "Mac" => check_mac,
            "ZeroValue" => check_zero_value,
            other => panic!("unknown group {other}"),
        };
        for test in &group.tests {
            check(test);
        }
    }
}
