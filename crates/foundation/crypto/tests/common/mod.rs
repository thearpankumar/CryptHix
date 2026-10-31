//! Helpers shared by the vector runners.

use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Reads a vector file under `tests/test-vectors/`.
pub(crate) fn load<T: DeserializeOwned>(relative: &str) -> T {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/test-vectors")
        .join(relative);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Decodes lowercase or uppercase hex.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Decodes hex of exactly `N` bytes.
pub(crate) fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex(text).try_into().expect("hex of the expected length")
}

/// A generated CryptHix set (format spec 20.2), with tests kept as JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VectorSet {
    pub(crate) number_of_tests: usize,
    pub(crate) test_groups: Vec<VectorGroup>,
}

/// One group of a generated set.
#[derive(Deserialize)]
pub(crate) struct VectorGroup {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) tests: Vec<Value>,
}

impl VectorSet {
    /// Loads a set and checks it has exactly the expected groups, in order, with these numbers of
    /// tests, so a generator change that drops cases fails here as well as in `vectors --check`.
    pub(crate) fn load_exact(relative: &str, groups: &[(&str, usize)]) -> Self {
        let set: VectorSet = load(relative);
        let found: Vec<(&str, usize)> = set
            .test_groups
            .iter()
            .map(|group| (group.kind.as_str(), group.tests.len()))
            .collect();
        assert_eq!(found, groups, "{relative}: groups and test counts");
        let total: usize = groups.iter().map(|(_, count)| count).sum();
        assert_eq!(set.number_of_tests, total, "{relative}: numberOfTests");
        set
    }
}

/// A text input of a generated test.
pub(crate) fn text<'a>(test: &'a Value, key: &str) -> &'a str {
    test["inputs"][key]
        .as_str()
        .unwrap_or_else(|| panic!("input {key}"))
}

/// A byte input of a generated test.
pub(crate) fn input(test: &Value, key: &str) -> Vec<u8> {
    hex(text(test, key))
}

/// A byte input of exactly `N` bytes.
pub(crate) fn input_array<const N: usize>(test: &Value, key: &str) -> [u8; N] {
    hex_array(text(test, key))
}

/// An expected byte output of a generated test.
pub(crate) fn output(test: &Value, key: &str) -> Vec<u8> {
    hex(test[key].as_str().unwrap_or_else(|| panic!("output {key}")))
}
