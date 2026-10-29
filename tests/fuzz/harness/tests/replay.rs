//! Runs every fuzz target on stable Rust: on each vector input, on one-bit mutations of the
//! short ones, and on every saved regression in `tests/fuzz/regressions/<target>/`.
//!
//! This keeps the fuzz properties in plain `cargo test`; `cargo xtask fuzz` searches further.

use std::fs;
use std::path::Path;

use crypthix_fuzz_harness::{OracleLimits, SMALL, TARGETS, Target, accepts, cbor_differential};
use crypthix_types::cbor::Document;
use crypthix_types::format_error::FormatError;
use crypthix_vector_gen::seeds;

/// Seeds up to this length also run with each bit flipped in turn.
const MUTATE_UP_TO: usize = 64;

fn target(name: &str) -> Target {
    let (_, run) = TARGETS
        .iter()
        .find(|(known, _)| *known == name)
        .unwrap_or_else(|| panic!("no target {name}"));
    *run
}

#[test]
fn every_vector_input_and_its_bit_flips() {
    let mut runs = 0usize;
    for seed in seeds() {
        for name in seed.target.fuzz_targets() {
            let run = target(name);
            run(&seed.bytes);
            runs += 1;
            if seed.bytes.len() <= MUTATE_UP_TO {
                for bit in 0..seed.bytes.len() * 8 {
                    let mut mutated = seed.bytes.clone();
                    mutated[bit / 8] ^= 1 << (bit % 8);
                    run(&mutated);
                    runs += 1;
                }
            }
        }
        // Any bytes drive the structured target.
        target("cbor_structured")(&seed.bytes);
    }
    assert!(runs > 10_000, "only {runs} runs");
}

#[test]
fn targets_match_the_fuzz_binaries() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz_targets");
    let mut binaries: Vec<String> = fs::read_dir(&dir)
        .expect("tests/fuzz/fuzz_targets")
        .map(|entry| entry.expect("readable entry").path())
        .filter_map(|path| {
            path.file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .collect();
    binaries.sort();
    let mut names: Vec<&str> = TARGETS.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    assert_eq!(
        names, binaries,
        "every fuzz binary has a body in TARGETS, and back"
    );
}

#[test]
fn every_saved_regression() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../regressions");
    for (name, run) in TARGETS {
        let dir = root.join(name);
        // Every target has a directory (with a .gitkeep), so a renamed target cannot silently
        // stop replaying its regressions.
        let entries = fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("{}: {error}; add it with a .gitkeep", dir.display()));
        for entry in entries {
            let path = entry.expect("readable entry").path();
            if path.file_name().is_some_and(|file| file == ".gitkeep") {
                continue;
            }
            let input =
                fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            run(&input);
        }
    }
}

/// `n` copies of the item `item` in an array.
fn array_of(n: u8, item: &[u8]) -> Vec<u8> {
    assert!(n < 24, "a one-byte array head");
    let mut out = vec![0x80 | n];
    for _ in 0..n {
        out.extend_from_slice(item);
    }
    out
}

/// A byte string of `len` bytes, `len` below 24.
fn short_bytes(len: u8) -> Vec<u8> {
    let mut out = vec![0x40 | len];
    out.resize(usize::from(len) + 1, 0x61);
    out
}

/// Every small limit at exactly its value and one over, on both sides of the differential.
/// Random fuzzing rarely lands on an exact length, so the boundaries are built here.
#[test]
fn small_limit_boundaries() {
    let nested = |depth: usize| [vec![0x81; depth - 1], vec![0x80]].concat();
    let map = |n: u8| {
        let mut out = vec![0xa0 | n];
        for key in 0..n {
            out.extend_from_slice(&[key, 0]);
        }
        out
    };
    let seven = array_of(7, &[0]);
    let six = array_of(6, &[0]);
    let items = |last: &[u8]| [&[0x84][..], &seven, &seven, &seven, last].concat();
    // 1 + 5 × 17 + 14 = 100 bytes, then one more.
    let document = |last: u8| {
        let mut out = vec![0x86];
        for _ in 0..5 {
            out.extend_from_slice(&short_bytes(16));
        }
        out.extend_from_slice(&short_bytes(last));
        out
    };
    let cases: [(&str, Vec<u8>, Vec<u8>); 7] = [
        ("document length", document(13), document(14)),
        (
            "byte string length",
            short_bytes(16),
            [vec![0x51], vec![0; 17]].concat(),
        ),
        (
            "text string length",
            [vec![0x70], vec![b'a'; 16]].concat(),
            [vec![0x71], vec![b'a'; 17]].concat(),
        ),
        ("array length", array_of(8, &[0]), array_of(9, &[0])),
        ("map length", map(8), map(9)),
        ("total items", items(&six), items(&seven)),
        ("depth", nested(4), nested(5)),
    ];
    for (limit, at, over) in cases {
        assert_eq!(
            Document::parse(&at, &SMALL).map(|_| ()),
            Ok(()),
            "{limit} at the limit"
        );
        assert_eq!(
            Document::parse(&over, &SMALL).map(|_| ()),
            Err(FormatError::Limit),
            "{limit} one over"
        );
        assert!(
            accepts(&at, &OracleLimits::SMALL),
            "oracle: {limit} at the limit"
        );
        assert!(
            !accepts(&over, &OracleLimits::SMALL),
            "oracle: {limit} one over"
        );
        cbor_differential(&at);
        cbor_differential(&over);
    }
}
