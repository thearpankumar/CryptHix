//! TV-03: deterministic CBOR (FS-08 to FS-11).

use crate::pre::{cat, h};
use crate::test_case::{Input, TestCase, t};
use crate::vector_set::VectorSet;

fn c(comment: &'static str, flags: &[&'static str], expect: &'static str, hex: &str) -> TestCase {
    t(comment, flags, expect, "cbor", h(hex))
}

/// Arrays nested `depth` deep, the innermost empty.
fn deep(depth: usize) -> Vec<u8> {
    cat(&[&vec![0x81; depth - 1], &[0x80]])
}

fn repeat(hex: &str, times: usize) -> String {
    hex.repeat(times)
}

#[rustfmt::skip]
#[allow(clippy::too_many_lines, reason = "one line per vector")]
fn document_tests() -> Vec<TestCase> {
    vec![
        c("unsigned 0", &["Valid"], "Ok", "00"),
        c("unsigned 23, the largest in the initial byte", &["Valid"], "Ok", "17"),
        c("unsigned 24, the smallest with a 1-byte argument", &["Valid"], "Ok", "1818"),
        c("unsigned 2^64 - 1", &["Valid"], "Ok", "1bffffffffffffffff"),
        c("negative -1", &["Valid"], "Ok", "20"),
        c("negative -2^63, the smallest allowed", &["Valid"], "Ok", "3b7fffffffffffffff"),
        c("byte string", &["Valid"], "Ok", "43010203"),
        c("text string with non-ASCII letters", &["Valid"], "Ok", "6ac3bc6e69636f6465c3a9"),
        c("false, true, null in an array", &["Valid"], "Ok", "83f4f5f6"),
        c("empty array and empty map", &["Valid"], "Ok", "8280a0"),
        c("key 24 (0x18 0x18) sorts before key -1 (0x20)", &["Valid", "BytewiseKeyOrder"], "Ok", "a21818f420f6"),
        c("keys 0, 1, 23, 24, 255, 256, -1, -24, -25", &["Valid", "BytewiseKeyOrder"], "Ok",
          concat!("a9", "0000", "0100", "1700", "181800", "18ff00", "19010000", "2000", "3700", "381800")),
        c("key 2^31 - 1 and key -2^31", &["Valid", "KeyRange"], "Ok", "a21a7fffffff003a7fffffff00"),
        t("nesting depth 8", &["Valid", "Depth"], "Ok", "cbor", deep(8)),
        c("5 in a 1-byte argument", &["NonShortestHead"], "NonCanonical", "1805"),
        c("255 in a 2-byte argument", &["NonShortestHead"], "NonCanonical", "1900ff"),
        c("65535 in a 4-byte argument", &["NonShortestHead"], "NonCanonical", "1a0000ffff"),
        c("2^32 - 1 in an 8-byte argument", &["NonShortestHead"], "NonCanonical", "1b00000000ffffffff"),
        c("byte-string length 2 in a 1-byte argument", &["NonShortestHead"], "NonCanonical", "58020102"),
        c("array count in a 2-byte argument", &["NonShortestHead"], "NonCanonical", "99000100"),
        c("map key -1 in a 1-byte argument", &["NonShortestHead"], "NonCanonical", "a1380000"),
        c("indefinite-length array", &["IndefiniteLength"], "NonCanonical", "9f01ff"),
        c("indefinite-length byte string", &["IndefiniteLength"], "NonCanonical", "5f4101ff"),
        c("indefinite-length map", &["IndefiniteLength"], "NonCanonical", "bf0100ff"),
        c("lone break code", &["IndefiniteLength"], "NonCanonical", "ff"),
        c("reserved additional information 28", &["Malformed"], "NonCanonical", "1c"),
        c("tag 0 on a text string", &["Tag"], "NonCanonical", "c06130"),
        c("tag 24 (embedded CBOR) on a byte string", &["Tag"], "NonCanonical", "d8184100"),
        c("tag inside an array", &["Tag"], "NonCanonical", "81c100"),
        c("half-precision float 0.0", &["Float"], "NonCanonical", "f90000"),
        c("single-precision float", &["Float"], "NonCanonical", "fa47c35000"),
        c("double-precision float as a map value", &["Float"], "NonCanonical", "a101fb3ff0000000000000"),
        c("undefined", &["SimpleValue"], "NonCanonical", "f7"),
        c("simple value 16", &["SimpleValue"], "NonCanonical", "f0"),
        c("simple value 255", &["SimpleValue"], "NonCanonical", "f8ff"),
        c("key -1 before key 24", &["KeyOrder"], "NonCanonical", "a220f41818f6"),
        c("keys 2 then 1", &["KeyOrder"], "NonCanonical", "a202000100"),
        c("duplicate key 1", &["DuplicateKey"], "NonCanonical", "a201000101"),
        c("duplicate key -1 in a nested map", &["DuplicateKey"], "NonCanonical", "81a220002001"),
        c("key 2^31", &["KeyRange"], "Schema", "a11a8000000000"),
        c("key -2^31 - 1", &["KeyRange"], "Schema", "a13a8000000000"),
        c("text key", &["KeyType"], "Schema", "a1616100"),
        c("byte-string key", &["KeyType"], "Schema", "a1410100"),
        c("boolean key", &["KeyType"], "Schema", "a1f500"),
        c("negative integer -2^63 - 1", &["IntegerRange"], "Schema", "3b8000000000000000"),
        c("invalid UTF-8", &["InvalidText"], "Schema", "62c328"),
        c("UTF-8 encoded surrogate", &["InvalidText"], "Schema", "63eda080"),
        c("line feed in text", &["ControlCharacter"], "Schema", "620a61"),
        c("NUL in text", &["ControlCharacter"], "Schema", "6100"),
        c("C1 control U+0085 in text", &["ControlCharacter"], "Schema", "62c285"),
        c("right-to-left override U+202E in a name", &["Bidi"], "Schema", "6561e280ae62"),
        c("Arabic letter mark U+061C", &["Bidi"], "Schema", "62d89c"),
        c("first strong isolate U+2068", &["Bidi"], "Schema", "63e281a8"),
        t("nesting depth 9", &["Depth"], "Limit", "cbor", deep(9)),
        c("byte string declares 5 bytes, 2 follow", &["LengthOverInput"], "Limit", "450102"),
        c("array declares 3 items, 1 follows", &["LengthOverInput"], "Limit", "8301"),
        c("array declares 2^64 - 1 items", &["LengthOverInput"], "Limit", "9bffffffffffffffff"),
        c("map declares 2^20 + 1 entries", &["LengthOverInput"], "Limit", "ba00100001"),
        c("byte string declares 16 MiB + 1", &["LengthOverInput"], "Limit", "5a01000001"),
        c("empty input", &["Truncated"], "Truncated", ""),
        c("2-byte argument cut short", &["Truncated"], "Truncated", "1901"),
        c("two top-level items", &["TrailingBytes"], "TrailingBytes", "0102"),
        c("array followed by a stray byte", &["TrailingBytes"], "TrailingBytes", "820102ff"),
        c("empty map followed by a byte", &["TrailingBytes"], "TrailingBytes", "a000"),
        c("tag as a map key", &["Tag", "ForbiddenKey"], "NonCanonical", "a1c00000"),
        c("float as a map key", &["Float", "ForbiddenKey"], "NonCanonical", "a1f93c0000"),
        c("undefined as a map key", &["SimpleValue", "ForbiddenKey"], "NonCanonical", "a1f700"),
        c("true as a map key: a valid item, but not an integer", &["KeyType"], "Schema", "a1f500"),
        c("simple value 20 in a 1-byte argument", &["NonShortestHead"], "NonCanonical", "f814"),
        c("simple value 24", &["SimpleValue"], "NonCanonical", "f818"),
        c("simple value 31", &["SimpleValue"], "NonCanonical", "f81f"),
        c("half float cut short", &["Truncated"], "Truncated", "f900"),
        c("reserved additional information 29", &["Malformed"], "NonCanonical", "1d"),
        c("reserved additional information 30", &["Malformed"], "NonCanonical", "1e"),
        c("empty text", &["Valid"], "Ok", "60"),
        c("4-byte UTF-8 character", &["Valid"], "Ok", "64f0908591"),
        c("no-break space U+00A0 is not a control character", &["Valid"], "Ok", "62c2a0"),
        c("overlong UTF-8", &["InvalidText"], "Schema", "62c080"),
        c("UTF-8 above U+10FFFF", &["InvalidText"], "Schema", "64f4908080"),
        c("UTF-8 sequence cut off inside the string", &["InvalidText"], "Schema", "62e282"),
        c("DEL U+007F", &["ControlCharacter"], "Schema", "617f"),
        c("C1 control U+0080", &["ControlCharacter"], "Schema", "62c280"),
        c("C1 control U+009F", &["ControlCharacter"], "Schema", "62c29f"),
        c("left-to-right mark U+200E", &["Bidi"], "Schema", "63e2808e"),
        c("right-to-left mark U+200F", &["Bidi"], "Schema", "63e2808f"),
        c("left-to-right embedding U+202A", &["Bidi"], "Schema", "63e280aa"),
        c("left-to-right isolate U+2066", &["Bidi"], "Schema", "63e281a6"),
        c("pop directional isolate U+2069", &["Bidi"], "Schema", "63e281a9"),
        c("positive bignum tag (RFC 8949 Appendix A)", &["Tag"], "NonCanonical", "c249010000000000000000"),
        c("negative bignum tag (RFC 8949 Appendix A)", &["Tag"], "NonCanonical", "c349010000000000000000"),
        c("-2^64 (RFC 8949 Appendix A)", &["IntegerRange"], "Schema", "3bffffffffffffffff"),
        c("bad text before a non-shortest head: the first item decides", &["ErrorOrder"], "Schema", "8261001805"),
        c("non-shortest head before bad text: the first item decides", &["ErrorOrder"], "NonCanonical", "8218056100"),
        c("count over the bytes left is decided at the container head", &["ErrorOrder", "LengthOverInput"], "Limit", "84180500"),
        c("map nesting depth 8", &["Valid", "Depth"], "Ok", &(repeat("a100", 7) + "a0")),
        c("map nesting depth 9", &["Depth"], "Limit", &(repeat("a100", 8) + "a0")),
        c("depth 9 reached inside a map value", &["Depth"], "Limit", &(String::from("a100") + &repeat("81", 7) + "80")),
        c("empty map at depth 9", &["Depth"], "Limit", &(repeat("81", 8) + "a0")),
    ]
}

#[rustfmt::skip]
fn nested_tests() -> Vec<TestCase> {
    vec![
        c("canonical map inside a byte string", &["Valid", "NestedDocument"], "Ok", "43a10100"),
        c("non-shortest integer inside a byte string", &["NestedDocument", "NonShortestHead"], "NonCanonical", "421805"),
        c("unsorted map inside a byte string", &["NestedDocument", "KeyOrder"], "NonCanonical", "45a202000100"),
        c("float inside a byte string", &["NestedDocument", "Float"], "NonCanonical", "43f90000"),
        c("outer item is not a byte string", &["NestedDocument", "KeyType"], "Schema", "a0"),
        c("declared length over the bytes left inside a byte string", &["NestedDocument", "LengthOverInput"], "Limit", "424501"),
        c("head cut short inside a byte string", &["NestedDocument"], "Truncated", "4119"),
    ]
}

/// Tests whose documents the runner builds, because they are too large to store.
#[rustfmt::skip]
fn generated_tests() -> Vec<TestCase> {
    const C: i64 = 1 << 20;
    vec![
        TestCase::new("array of exactly 2^20 items", &["ContainerLimit"], "Ok", vec![("flat", Input::Int(C))]),
        TestCase::new("array of 2^20 + 1 items", &["ContainerLimit"], "Limit", vec![("flat", Input::Int(C + 1))]),
        TestCase::new("exactly 2^22 items in one document", &["TotalItemLimit"], "Ok",
            vec![("inner", Input::Ints(vec![C - 1, C - 1, C - 1, C - 2]))]),
        TestCase::new("2^22 + 1 items in one document", &["TotalItemLimit"], "Limit",
            vec![("inner", Input::Ints(vec![C - 1; 4]))]),
    ]
}

#[rustfmt::skip]
pub(crate) fn set() -> VectorSet {
    VectorSet {
        file: "tv-03-cbor.json",
        set: "TV-03",
        structure: "cbor-document",
        seed: None,
        extra: vec![("limits", "Limits::FORMAT_0")],
        notes: vec![
            ("Valid", &["FS-08", "M-37"], "Canonical CBOR of the allowed subset"),
            ("BytewiseKeyOrder", &["FS-08", "M-37", "T-83"], "Keys sorted by their encoded bytes, not by value or length first"),
            ("NonShortestHead", &["FS-08", "M-37", "T-83"], "An argument in a wider head than needed"),
            ("IndefiniteLength", &["FS-08", "T-83"], "Indefinite length or break code"),
            ("Malformed", &["FS-08", "T-39"], "Reserved additional information value"),
            ("Tag", &["FS-08", "T-83"], "A tag anywhere in the document"),
            ("Float", &["FS-08", "T-83"], "A floating-point value"),
            ("SimpleValue", &["FS-08", "T-83"], "A simple value other than false, true and null"),
            ("KeyOrder", &["FS-08", "M-37", "T-83"], "Map keys not in bytewise order"),
            ("DuplicateKey", &["FS-08", "M-37", "T-83"], "The same key twice in a map"),
            ("KeyRange", &["FS-09", "T-83"], "Map key at or outside the i32 range"),
            ("KeyType", &["FS-09", "T-83"], "Map key that is not an integer"),
            ("IntegerRange", &["FS-09", "T-39"], "Negative integer below -2^63"),
            ("InvalidText", &["FS-10", "T-39"], "Text string that is not valid UTF-8"),
            ("ControlCharacter", &["FS-10", "T-83"], "C0 or C1 control character in text (Unicode Cc)"),
            ("Bidi", &["FS-10", "T-83"], "Bidirectional formatting character in text"),
            ("Depth", &["FS-11", "T-39"], "Nesting depth at or above the limit of 8"),
            ("LengthOverInput", &["FS-11", "T-39"], "A declared length or count larger than the input or a limit, rejected before allocating"),
            ("Truncated", &["FS-11", "T-39"], "Input ends inside a head"),
            ("TrailingBytes", &["FS-08", "T-83"], "Bytes after the single top-level item"),
            ("NestedDocument", &["FS-08", "M-37", "T-83"], "CBOR carried in a byte string is checked again with its own budget"),
            ("ForbiddenKey", &["FS-08", "FS-93", "T-83"], "A tag, float or simple value as a map key: the encoding rule wins over the key rule"),
            ("ErrorOrder", &["FS-93", "T-83"], "Several errors; items are checked in byte order and the first failing check decides"),
            ("ContainerLimit", &["FS-11", "T-39"], "Items in one array at and over 2^20 (built by the runner: inputs.flat zero items)"),
            ("TotalItemLimit", &["FS-11", "T-39"], "Items in one document at and over 2^22 (built by the runner: an array of arrays of zeros with lengths inputs.inner)"),
        ],
        groups: vec![
            ("DocumentParse", document_tests()),
            ("NestedDocumentParse", nested_tests()),
            ("GeneratedDocumentParse", generated_tests()),
        ],
    }
}
