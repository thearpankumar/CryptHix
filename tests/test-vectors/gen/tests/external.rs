//! Vendored vectors under `external/` keep their provenance and parse (format spec 20.1).

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// Every source format spec 20.1 lists.
const SOURCES: [&str; 8] = [
    "blake3",
    "ed25519-speccheck",
    "rfc5869",
    "rfc8032",
    "rfc8439",
    "rfc9106",
    "wycheproof",
    "xchacha-draft",
];

fn external() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../external")
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| entry.expect("entry").path())
        .collect();
    files.sort();
    files
}

#[test]
fn every_source_has_provenance_and_a_licence() {
    let mut found: Vec<String> = files(&external())
        .iter()
        .filter(|path| path.is_dir())
        .map(|path| {
            path.file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    found.sort();
    assert_eq!(
        found, SOURCES,
        "external/ holds exactly the sources of format spec 20.1"
    );
    for source in SOURCES {
        let dir = external().join(source);
        let provenance = fs::read_to_string(dir.join("SOURCE")).expect("SOURCE file");
        assert!(
            provenance.contains("commit:") || provenance.contains("status:     not transcribed"),
            "{source}/SOURCE pins a commit or says the vectors are not transcribed yet"
        );
        let licence = fs::read_to_string(dir.join("LICENSE")).expect("LICENSE file");
        assert!(!licence.trim().is_empty(), "{source}/LICENSE is empty");
    }
}

#[test]
fn every_vendored_file_is_listed_and_parses() {
    for source in SOURCES {
        let dir = external().join(source);
        let provenance = fs::read_to_string(dir.join("SOURCE")).expect("SOURCE file");
        for path in files(&dir) {
            let name = path
                .file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned();
            if name == "SOURCE" || name == "LICENSE" {
                continue;
            }
            assert!(
                provenance.contains(&format!("-> {name}")),
                "{source}/{name} is not listed in SOURCE"
            );
            let text = fs::read_to_string(&path).expect("UTF-8");
            let value: Value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{source}/{name}: {error}"));
            if source == "wycheproof" {
                check_wycheproof_count(&value, &name);
            }
        }
    }
}

/// A truncated or edited Wycheproof file no longer matches its own test count.
fn check_wycheproof_count(file: &Value, name: &str) {
    let declared = file["numberOfTests"].as_u64().expect("numberOfTests");
    let counted: usize = file["testGroups"]
        .as_array()
        .expect("testGroups")
        .iter()
        .map(|group| group["tests"].as_array().expect("tests").len())
        .sum();
    assert_eq!(counted as u64, declared, "{name}");
}
