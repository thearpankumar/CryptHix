//! Every vector file matches `schema/vector-file.schema.json`, and the schema rejects broken
//! files.

use std::fs;
use std::path::{Path, PathBuf};

use crypthix_types::format_error::FormatError;
use serde_json::{Value, json};

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn load(path: &Path) -> Value {
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn validator() -> jsonschema::Validator {
    let schema = load(&vectors_root().join("schema/vector-file.schema.json"));
    jsonschema::draft202012::new(&schema).expect("the schema is valid draft 2020-12")
}

fn vector_files() -> Vec<PathBuf> {
    let dir = vectors_root().join("crypthix/v0");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("vector directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    files
}

#[test]
fn every_vector_file_matches_the_schema() {
    let validator = validator();
    let files = vector_files();
    assert!(files.len() >= 3, "TV-02, TV-03 and TV-17 at least");
    for path in files {
        let errors: Vec<String> = validator
            .iter_errors(&load(&path))
            .map(|error| format!("{} at {}", error, error.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "{}:\n{}",
            path.display(),
            errors.join("\n")
        );
    }
}

#[test]
fn expect_names_are_the_format_errors() {
    let schema = load(&vectors_root().join("schema/vector-file.schema.json"));
    let names: Vec<&str> = schema["$defs"]["expect"]["enum"]
        .as_array()
        .expect("enum")
        .iter()
        .map(|name| name.as_str().expect("string"))
        .collect();
    let mut expected = vec!["Ok"];
    expected.extend(FormatError::ALL.iter().map(|error| error.name()));
    expected.extend(CX_AEAD_CAUSES);
    assert_eq!(names, expected);
}

/// The two CX-AEAD failure causes that exist only inside `crypthix-crypto` (FS-28).
const CX_AEAD_CAUSES: [&str; 2] = ["Commitment", "AeadTag"];

#[test]
fn only_tv05_expects_the_cx_aead_causes() {
    for path in vector_files() {
        let file = load(&path);
        let uses_causes = file["testGroups"]
            .as_array()
            .expect("testGroups")
            .iter()
            .flat_map(|group| group["tests"].as_array().expect("tests"))
            .any(|test| CX_AEAD_CAUSES.contains(&test["expect"].as_str().expect("expect")));
        let is_tv05 = file["set"] == "TV-05";
        assert!(
            !uses_causes || is_tv05,
            "{} expects Commitment or AeadTag; only TV-05 may (FS-94)",
            path.display()
        );
    }
}

/// A copy of TV-02 with `change` applied must fail validation.
fn rejects(what: &str, change: impl FnOnce(&mut Value)) {
    let mut file = load(&vectors_root().join("crypthix/v0/tv-02-preamble.json"));
    change(&mut file);
    assert!(!validator().is_valid(&file), "the schema accepts {what}");
}

#[test]
fn broken_files_are_rejected() {
    let test = |file: &mut Value| file["testGroups"][0]["tests"][0].clone();
    rejects("a test without expect", |file| {
        let mut first = test(file);
        first.as_object_mut().expect("object").remove("expect");
        file["testGroups"][0]["tests"][0] = first;
    });
    rejects("an unknown expect name", |file| {
        file["testGroups"][0]["tests"][0]["expect"] = json!("Bogus");
    });
    rejects("uppercase hex", |file| {
        file["testGroups"][0]["tests"][0]["inputs"]["file"] = json!("89CHX");
    });
    rejects("odd-length hex", |file| {
        file["testGroups"][0]["tests"][0]["inputs"]["file"] = json!("894");
    });
    rejects("a note without cites", |file| {
        file["notes"]["Valid"] = json!({"description": "x"});
    });
    rejects("a note citing no FS rule", |file| {
        file["notes"]["Valid"]["cites"] = json!(["T-39"]);
    });
    rejects("a note citing no M- or T- ID", |file| {
        file["notes"]["Valid"]["cites"] = json!(["FS-06"]);
    });
    rejects("a cite that is not a rule ID", |file| {
        file["notes"]["Valid"]["cites"] = json!(["section 5"]);
    });
    rejects("a test with no flags", |file| {
        file["testGroups"][0]["tests"][0]["flags"] = json!([]);
    });
    rejects("a missing numberOfTests", |file| {
        file.as_object_mut()
            .expect("object")
            .remove("numberOfTests");
    });
    rejects("a short seed", |file| {
        file["seed"] = json!("00ff");
    });
    rejects("a numeric header extra", |file| {
        file["limits"] = json!(3);
    });
}
