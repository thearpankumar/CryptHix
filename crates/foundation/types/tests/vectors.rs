//! Runs the CryptHix format vectors this crate owns, laid out as in format spec section 20:
//! TV-02 (preamble), TV-03 (deterministic CBOR) and TV-17 (versions, criticality, feature bits
//! and GREASE).

use std::fs;
use std::path::PathBuf;

use crypthix_types::cbor::{Document, Encoder, Limits};
use crypthix_types::format_error::FormatError;
use crypthix_types::preamble::Preamble;
use crypthix_types::registry::Features;
use crypthix_types::store_key::StoreKey;
use serde_json::Value;

fn repo_file(relative: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "../../..", relative]
        .iter()
        .collect();
    fs::read_to_string(&path).expect("repository file is readable")
}

fn vector_file(name: &str) -> Value {
    let text = repo_file(&format!("tests/test-vectors/crypthix/v0/{name}"));
    serde_json::from_str(&text).expect("vector file is JSON")
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex input is a string");
    assert!(text.len().is_multiple_of(2), "odd-length hex {text}");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digits"))
        .collect()
}

fn outcome(result: Result<(), FormatError>) -> &'static str {
    match result {
        Ok(()) => "Ok",
        Err(error) => error.name(),
    }
}

/// Whether a cited ID is defined: FS rules in the format spec, M- and T- IDs in the threat
/// model (FS-94).
fn is_defined(cite: &str, spec: &str, threat_model: &str) -> bool {
    if cite.starts_with("FS-") {
        spec.contains(&format!("**{cite}.**"))
    } else {
        threat_model.contains(&format!("| {cite} |"))
    }
}

/// Checks the file header and notes, then runs every test through `run` and compares the
/// result with `expect`.
fn run_set(name: &str, set: &str, run: impl Fn(&str, &Value) -> Result<(), FormatError>) {
    let spec = repo_file("docs/format-spec.md");
    let threat_model = repo_file("docs/threat-model.md");
    let file = vector_file(name);
    assert_eq!(file["set"], set);
    assert_eq!(file["formatVersion"], 0);
    assert_eq!(file["suiteId"], 1);
    let notes = file["notes"].as_object().expect("notes");
    for (flag, note) in notes {
        let cites: Vec<&str> = note["cites"]
            .as_array()
            .expect("cites")
            .iter()
            .map(|cite| cite.as_str().expect("cite is a string"))
            .collect();
        assert!(
            cites.iter().any(|cite| cite.starts_with("FS-"))
                && cites
                    .iter()
                    .any(|cite| cite.starts_with("M-") || cite.starts_with("T-")),
            "{set} flag {flag} must cite an FS rule and an M- or T- ID (FS-94)"
        );
        for cite in cites {
            assert!(
                is_defined(cite, &spec, &threat_model),
                "{set} flag {flag} cites unknown {cite}"
            );
        }
    }
    let mut count = 0;
    for group in file["testGroups"].as_array().expect("test groups") {
        let group_type = group["type"].as_str().expect("group type");
        for test in group["tests"].as_array().expect("tests") {
            count += 1;
            for flag in test["flags"].as_array().expect("flags") {
                let flag = flag.as_str().expect("flag name");
                assert!(notes.contains_key(flag), "{set} flag {flag} has no note");
            }
            let expect = test["expect"].as_str().expect("expect");
            assert!(
                expect == "Ok" || FormatError::ALL.iter().any(|error| error.name() == expect),
                "{set} tcId {}: unknown expect {expect}",
                test["tcId"]
            );
            let got = outcome(run(group_type, &test["inputs"]));
            assert_eq!(
                got, expect,
                "{set} tcId {}: {}",
                test["tcId"], test["comment"]
            );
        }
    }
    assert_eq!(file["numberOfTests"], count);
}

/// An array of `count` zeros.
fn zeros(encoder: &mut Encoder, count: u64) -> Result<(), FormatError> {
    encoder.array(|items| {
        for _ in 0..count {
            items.uint(0);
        }
        Ok(())
    })
}

/// The document a generated TV-03 test describes, built with the encoder. Only for documents
/// within the limits, since the encoder refuses to finish any other.
fn generated_document(inputs: &Value) -> Vec<u8> {
    let mut encoder = Encoder::new();
    let written = if let Some(count) = inputs["flat"].as_u64() {
        zeros(&mut encoder, count)
    } else {
        let lengths: Vec<u64> = inputs["inner"]
            .as_array()
            .expect("inner lengths")
            .iter()
            .map(|length| length.as_u64().expect("length"))
            .collect();
        encoder.array(|outer| lengths.iter().try_for_each(|length| zeros(outer, *length)))
    };
    written.expect("encodes");
    encoder
        .finish(&Limits::FORMAT_0)
        .expect("only documents within the limits are compared")
}

/// The same document as [`generated_document`], encoded by hand so that documents over the
/// limits can be built too.
fn raw_bytes(inputs: &Value) -> Vec<u8> {
    fn head(out: &mut Vec<u8>, major: u8, count: u64) {
        let major = major << 5;
        match count {
            0..=23 => out.push(major | u8::try_from(count).expect("small")),
            24..=0xff => out.extend_from_slice(&[major | 0x18, u8::try_from(count).expect("byte")]),
            0x100..=0xffff => {
                out.push(major | 0x19);
                out.extend_from_slice(&u16::try_from(count).expect("u16").to_be_bytes());
            }
            _ => {
                out.push(major | 0x1a);
                out.extend_from_slice(&u32::try_from(count).expect("u32").to_be_bytes());
            }
        }
    }
    let mut out = Vec::new();
    let zeros = |out: &mut Vec<u8>, count: u64| {
        head(out, 4, count);
        out.resize(out.len() + usize::try_from(count).expect("fits"), 0);
    };
    if let Some(count) = inputs["flat"].as_u64() {
        zeros(&mut out, count);
    } else {
        let lengths = inputs["inner"].as_array().expect("inner lengths");
        head(&mut out, 4, lengths.len() as u64);
        for length in lengths {
            zeros(&mut out, length.as_u64().expect("length"));
        }
    }
    out
}

#[test]
fn tv_02_preamble() {
    run_set("tv-02-preamble.json", "TV-02", |group_type, inputs| {
        let file = hex(&inputs["file"]);
        match group_type {
            "PreambleParse" => Preamble::parse(&file).map(|_| ()),
            "PreambleAtPath" => {
                let path = inputs["path"].as_str().expect("path");
                let key = StoreKey::parse(path)?.expect("vector paths are store names");
                let (preamble, _) = Preamble::parse(&file)?;
                key.check_type(preamble.file_type())
            }
            other => panic!("unknown TV-02 group type {other}"),
        }
    });
}

#[test]
fn tv_03_cbor() {
    run_set("tv-03-cbor.json", "TV-03", |group_type, inputs| {
        let bytes = match group_type {
            "GeneratedDocumentParse" => raw_bytes(inputs),
            _ => hex(&inputs["cbor"]),
        };
        let document = Document::parse(&bytes, &Limits::FORMAT_0)?;
        match group_type {
            "DocumentParse" | "GeneratedDocumentParse" => Ok(()),
            "NestedDocumentParse" => document
                .root()
                .nested_document(&Limits::FORMAT_0)
                .map(|_| ()),
            other => panic!("unknown TV-03 group type {other}"),
        }
    });
}

#[test]
fn tv_03_generated_documents_match_the_encoder() {
    // The hand-built documents of the generated group equal what the encoder writes.
    for inputs in [
        serde_json::json!({ "flat": 3 }),
        serde_json::json!({ "flat": 1 << 20 }),
        serde_json::json!({ "inner": [0, 24, 300] }),
    ] {
        assert_eq!(generated_document(&inputs), raw_bytes(&inputs), "{inputs}");
    }
}

#[test]
fn tv_17_versions() {
    run_set(
        "tv-17-versions.json",
        "TV-17",
        |group_type, inputs| match group_type {
            "MapKeys" => {
                let bytes = hex(&inputs["cbor"]);
                let document = Document::parse(&bytes, &Limits::FORMAT_0)?;
                let mut map = document.root().map()?;
                for key in inputs["known"].as_array().expect("known keys") {
                    let key = i32::try_from(key.as_i64().expect("integer key")).expect("i32 key");
                    map.required(key)?;
                }
                map.finish().map(|_| ())
            }
            "Features" => {
                let bits = |name: &str| -> u64 {
                    inputs[name]
                        .as_str()
                        .expect("decimal string")
                        .parse()
                        .expect("u64")
                };
                let features = Features::new(bits("compat"), bits("roCompat"), bits("incompat"));
                match inputs["mode"].as_str().expect("mode") {
                    "read" => features.check_read(Features::EMPTY),
                    "write" => features.check_write(Features::EMPTY),
                    other => panic!("unknown mode {other}"),
                }
            }
            "PreambleVersions" => Preamble::parse(&hex(&inputs["file"])).map(|_| ()),
            other => panic!("unknown TV-17 group type {other}"),
        },
    );
}
