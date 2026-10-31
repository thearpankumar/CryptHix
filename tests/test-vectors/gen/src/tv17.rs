//! TV-17: versions, criticality, feature bits and GREASE (FS-16 to FS-22).

use crate::pre::{Pre, h};
use crate::test_case::{Input, TestCase, t};
use crate::vector_set::VectorSet;

/// A map whose keys a reader knowing only `known` checks.
fn keys(
    hex: &str,
    known: &[i64],
    comment: &'static str,
    flags: &[&'static str],
    expect: &'static str,
) -> TestCase {
    TestCase::new(
        comment,
        flags,
        expect,
        vec![
            ("cbor", Input::Bytes(h(hex))),
            ("known", Input::Ints(known.to_vec())),
        ],
    )
}

/// Feature bits checked for `mode` ("read" or "write"). Bits are decimal strings, because
/// bit 63 does not fit every JSON reader's integers.
fn feat(
    comment: &'static str,
    flags: &[&'static str],
    expect: &'static str,
    [compat, ro_compat, incompat]: [u64; 3],
    mode: &'static str,
) -> TestCase {
    TestCase::new(
        comment,
        flags,
        expect,
        vec![
            ("compat", Input::Text(compat.to_string())),
            ("roCompat", Input::Text(ro_compat.to_string())),
            ("incompat", Input::Text(incompat.to_string())),
            ("mode", Input::Text(mode.to_owned())),
        ],
    )
}

/// The GREASE bits 42, 58 and 63.
const G: u64 = (1 << 42) | (1 << 58) | (1 << 63);

#[rustfmt::skip]
fn key_tests() -> Vec<TestCase> {
    vec![
        keys("a10100", &[], "unknown non-critical key 1", &["NonCriticalKey"], "Ok"),
        keys("a1191000f6", &[], "unknown non-critical key 4096, outside safe-to-copy", &["NonCriticalKey"], "Ok"),
        keys("a12100", &[], "unknown critical key -2", &["CriticalKey"], "UnknownCritical"),
        keys("a2010020f5", &[1], "unknown critical key -1 after a known key", &["CriticalKey"], "UnknownCritical"),
        keys("a2010020f5", &[1, -1], "every critical key known", &["CriticalKey"], "Ok"),
        keys("a1190a0a00", &[], "positive GREASE key 0x0A0A", &["GreaseKey"], "Ok"),
        keys("a1390a0900", &[], "negative GREASE key -0x0A0A is not critical", &["GreaseKey"], "Ok"),
        keys("a139faf900", &[], "negative GREASE key -0xFAFA is not critical", &["GreaseKey"], "Ok"),
        keys("a1390a0a00", &[], "-0x0A0B is not GREASE and is critical", &["GreaseKey", "CriticalKey"], "UnknownCritical"),
    ]
}

#[rustfmt::skip]
fn feature_tests() -> Vec<TestCase> {
    vec![
        feat("no bits", &["FeatureBits"], "Ok", [0, 0, 0], "read"),
        feat("unknown compat bit 7 on write", &["FeatureBits"], "Ok", [1 << 7, 0, 0], "write"),
        feat("unknown ro_compat bit 0 (log) on read", &["FeatureBits"], "Ok", [0, 1, 0], "read"),
        feat("unknown ro_compat bit 0 (log) on write", &["FeatureBits"], "Feature", [0, 1, 0], "write"),
        feat("unknown incompat bit 3 (several writers) on read", &["FeatureBits"], "Feature", [0, 0, 1 << 3], "read"),
        feat("unknown incompat bit 41 on read", &["FeatureBits"], "Feature", [0, 0, 1 << 41], "read"),
        feat("GREASE bits in every set on write", &["FeatureBits", "GreaseBit"], "Ok", [G, G, G], "write"),
    ]
}

#[rustfmt::skip]
fn version_tests() -> Vec<TestCase> {
    let file = |change: fn(&mut Pre)| {
        let mut fields = Pre::KEYRING;
        change(&mut fields);
        fields.bytes()
    };
    vec![
        t("GREASE format version", &["UnknownVersion", "GreaseValue"], "UnsupportedFormat", "file", file(|p| p.fmt = 0x1A1A)),
        t("GREASE suite", &["UnknownVersion", "GreaseValue"], "UnsupportedSuite", "file", file(|p| p.suite = 0x1A1A)),
        t("suite 0x0002", &["UnknownVersion"], "UnsupportedSuite", "file", file(|p| p.suite = 2)),
        t("struct version 2 of a known type", &["UnknownVersion"], "UnsupportedStruct", "file", file(|p| p.sv = 2)),
    ]
}

#[rustfmt::skip]
pub(crate) fn set() -> VectorSet {
    VectorSet {
        file: "tv-17-versions.json",
        set: "TV-17",
        structure: "versions-criticality-features",
        seed: None,
        extra: vec![("knownFeatures", "Features::EMPTY (a Phase 1 reader knows no feature bits)")],
        notes: vec![
            ("NonCriticalKey", &["FS-20", "M-33"], "An unknown non-negative key is ignored for meaning and kept"),
            ("CriticalKey", &["FS-09", "FS-20", "M-33", "T-78"], "An unknown negative key rejects the structure"),
            ("GreaseKey", &["FS-22", "M-33"], "GREASE keys of either sign are never critical"),
            ("FeatureBits", &["FS-21", "M-33", "T-78"], "compat ignored; ro_compat blocks writes; incompat blocks reads"),
            ("GreaseBit", &["FS-22", "M-33"], "GREASE bits 42, 58 and 63 are ignored"),
            ("UnknownVersion", &["FS-16", "FS-19", "M-33", "T-78"], "No fallback to another format, suite or struct version"),
            ("GreaseValue", &["FS-22", "M-33"], "A GREASE value where only assigned values are valid"),
        ],
        groups: vec![
            ("MapKeys", key_tests()),
            ("Features", feature_tests()),
            ("PreambleVersions", version_tests()),
        ],
    }
}
