//! TV-02: the preamble (FS-06, FS-07).

use crate::pre::{MAGIC, Pre, cat, pre};
use crate::test_case::{Input, TestCase, t};
use crate::vector_set::VectorSet;

fn file(
    comment: &'static str,
    flags: &[&'static str],
    expect: &'static str,
    bytes: Vec<u8>,
) -> TestCase {
    t(comment, flags, expect, "file", bytes)
}

fn at_path(
    comment: &'static str,
    expect: &'static str,
    path: &'static str,
    bytes: Vec<u8>,
) -> TestCase {
    let flags: &[&str] = if expect == "Ok" {
        &["Valid"]
    } else {
        &["TypeNotPath"]
    };
    TestCase::new(
        comment,
        flags,
        expect,
        vec![
            ("path", Input::Text(path.to_owned())),
            ("file", Input::Bytes(bytes)),
        ],
    )
}

/// A keyring preamble with one field changed.
fn keyring(change: impl FnOnce(&mut Pre)) -> Vec<u8> {
    let mut fields = Pre::KEYRING;
    change(&mut fields);
    fields.bytes()
}

fn with_type(typ: u8) -> Vec<u8> {
    keyring(|p| p.typ = typ)
}

#[rustfmt::skip]
#[allow(clippy::too_many_lines, reason = "one line per vector")]
fn parse_tests() -> Vec<TestCase> {
    let base = Pre::KEYRING.bytes();
    vec![
        file("keyring with a 3-byte body", &["Valid"], "Ok", cat(&[&pre(0x03, 3), b"abc"])),
        file("vault config with an empty body", &["Valid"], "Ok", pre(0x01, 0)),
        file("device set declaring its 1 MiB cap but carrying no body", &["ShortBody"], "Truncated", pre(0x10, 1 << 20)),
        file("first magic byte changed", &["WrongMagic"], "Magic", cat(&[b"\x88", &base[1..]])),
        file("high bit stripped by a 7-bit channel", &["WrongMagic"], "Magic", cat(&[b"\x09", &base[1..]])),
        file("CR LF turned into LF", &["WrongMagic"], "Magic", cat(&[b"\x89CHX\n\x1a\n", &base[8..]])),
        file("not a CryptHix file", &["WrongMagic"], "Magic", cat(&[b"PK\x03\x04", &[0; 16]])),
        file("empty file", &["ShortPreamble"], "Truncated", Vec::new()),
        file("magic only", &["ShortPreamble"], "Truncated", MAGIC.to_vec()),
        file("19 of 20 preamble bytes", &["ShortPreamble"], "Truncated", base[..19].to_vec()),
        file("format version 1", &["UnknownFormat"], "UnsupportedFormat", keyring(|p| p.fmt = 1)),
        file("GREASE format version 0x0A0A", &["UnknownFormat", "Grease"], "UnsupportedFormat", keyring(|p| p.fmt = 0x0A0A)),
        file("suite 0", &["UnknownSuite"], "UnsupportedSuite", keyring(|p| p.suite = 0)),
        file("suite 2", &["UnknownSuite"], "UnsupportedSuite", keyring(|p| p.suite = 2)),
        file("unassigned type 0x00", &["UnknownType"], "UnknownType", with_type(0x00)),
        file("unassigned type 0x11", &["UnknownType"], "UnknownType", with_type(0x11)),
        file("nested type 0x20 (manifest) used as a file", &["NestedTypeAsFile"], "UnknownType", with_type(0x20)),
        file("private-use type 0xF0 read from a store", &["UnknownType"], "UnknownType", with_type(0xF0)),
        file("struct version 0", &["UnknownStruct"], "UnsupportedStruct", keyring(|p| p.sv = 0)),
        file("struct version 2", &["UnknownStruct"], "UnsupportedStruct", keyring(|p| p.sv = 2)),
        file("flags 0x0001", &["NonZeroFlags"], "Flags", keyring(|p| p.flags = 1)),
        file("flags 0x8000", &["NonZeroFlags"], "Flags", keyring(|p| p.flags = 0x8000)),
        file("keyring body_len 4097, one over its cap", &["OverCap"], "Limit", pre(0x03, 4097)),
        file("shard body_len 2^24 + 169, one over its cap", &["OverCap"], "Limit", pre(0x08, (1 << 24) + 169)),
        file("body_len 0xFFFFFFFF", &["OverCap"], "Limit", pre(0x04, 0xFFFF_FFFF)),
        file("one byte past body_len", &["TrailingBytes"], "TrailingBytes", cat(&[&pre(0x03, 2), b"abc"])),
        file("one byte short of body_len", &["ShortBody"], "Truncated", cat(&[&pre(0x03, 4), b"abc"])),
        file("format checked before type", &["CheckOrder"], "UnsupportedFormat", keyring(|p| (p.typ, p.fmt, p.flags) = (0xFF, 7, 1))),
        file("type checked before flags", &["CheckOrder"], "UnknownType", keyring(|p| (p.typ, p.flags) = (0xFF, 1))),
        file("flags checked before length", &["CheckOrder"], "Flags", keyring(|p| (p.flags, p.body_len) = (1, 9))),
        file("19-byte file with a bad fmt: length is checked first", &["CheckOrder", "ShortPreamble"], "Truncated", keyring(|p| p.fmt = 7)[..19].to_vec()),
        file("7-byte prefix of the magic", &["ShortPreamble"], "Truncated", MAGIC[..7].to_vec()),
        file("magic with its last byte changed", &["WrongMagic"], "Magic", cat(&[&MAGIC[..7], b"\x0b", &base[8..]])),
        file("reserved-phase type 0x0B (log segment) is a known type", &["Valid"], "Ok", with_type(0x0B)),
        file("reserved-phase type 0x0C (snapshot root) is a known type", &["Valid"], "Ok", with_type(0x0C)),
        file("reserved-phase type 0x0E (log key) is a known type", &["Valid"], "Ok", with_type(0x0E)),
        file("reserved-phase type 0x0F (token wrapper) is a known type", &["Valid"], "Ok", with_type(0x0F)),
        file("last nested code 0x2F", &["NestedTypeAsFile"], "UnknownType", with_type(0x2F)),
        file("unassigned type 0x30", &["UnknownType"], "UnknownType", with_type(0x30)),
        file("unassigned type 0xEF", &["UnknownType"], "UnknownType", with_type(0xEF)),
        file("private-use type 0xFF", &["UnknownType"], "UnknownType", with_type(0xFF)),
        file("GREASE suite 0x0A0A", &["UnknownSuite", "Grease"], "UnsupportedSuite", keyring(|p| p.suite = 0x0A0A)),
        file("GREASE flags 0x0A0A", &["NonZeroFlags", "Grease"], "Flags", keyring(|p| p.flags = 0x0A0A)),
        file("keyring body exactly at its 4096-byte cap", &["Valid"], "Ok", cat(&[&pre(0x03, 4096), &[0; 4096]])),
    ]
}

#[rustfmt::skip]
fn path_tests() -> Vec<TestCase> {
    vec![
        at_path("vault config at configs/1.chx", "Ok", "configs/1.chx", pre(0x01, 0)),
        at_path("vault config stored as a keyring", "NameMismatch", "keys/keyring-1.chx", pre(0x01, 0)),
        at_path("vault root stored as a config", "NameMismatch", "configs/1.chx", pre(0x09, 0)),
        at_path("device-local device state stored under a root name", "NameMismatch", "roots/00000000000000000002.chx", pre(0x0A, 0)),
        at_path(
            "device-local queue job stored as a shard",
            "NameMismatch",
            "shards/ab/abababababababababababababababababababababababababababababababab.chx",
            pre(0x0D, 0),
        ),
        at_path("shard stored under a root name", "NameMismatch", "roots/00000000000000000001.chx", pre(0x08, 0)),
    ]
}

#[rustfmt::skip]
pub(crate) fn set() -> VectorSet {
    VectorSet {
        file: "tv-02-preamble.json",
        set: "TV-02",
        structure: "preamble",
        extra: Vec::new(),
        notes: vec![
            ("Valid", &["FS-06", "FS-07", "T-39"], "A well-formed preamble"),
            ("WrongMagic", &["FS-06", "T-39"], "The first 8 bytes are not the magic"),
            ("ShortPreamble", &["FS-07", "T-39"], "Fewer than 20 bytes"),
            ("UnknownFormat", &["FS-16", "M-33", "T-78"], "Format version this build does not support"),
            ("UnknownSuite", &["FS-05", "FS-16", "M-33", "T-78"], "Suite other than 0x0001"),
            ("UnknownType", &["FS-06", "T-83"], "Unassigned or private-use file type"),
            ("NestedTypeAsFile", &["FS-06", "FS-13", "M-37", "T-83"], "A nested type code used as a file type"),
            ("UnknownStruct", &["FS-19", "M-33"], "Struct version other than 1"),
            ("NonZeroFlags", &["FS-07", "T-83"], "Preamble flags not zero"),
            ("OverCap", &["FS-07", "FS-11", "T-39"], "body_len above the cap for the type, rejected before reading the body"),
            ("TrailingBytes", &["FS-07", "T-83"], "Bytes after body_len"),
            ("ShortBody", &["FS-07", "T-39"], "Fewer body bytes than body_len"),
            ("CheckOrder", &["FS-93", "T-83"], "Several fields wrong; the first check in the documented order wins"),
            ("Grease", &["FS-22", "M-33"], "A GREASE value where only assigned values are valid"),
            ("TypeNotPath", &["FS-06", "FS-92", "T-83"], "File type does not match the store name"),
        ],
        groups: vec![("PreambleParse", parse_tests()), ("PreambleAtPath", path_tests())],
    }
}
