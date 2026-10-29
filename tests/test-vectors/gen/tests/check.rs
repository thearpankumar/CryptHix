//! The committed vector files are exactly what the generator writes (FS-94).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use crypthix_vector_gen::{Problem, check, sets};

/// A scratch directory removed when the test ends, even if it fails.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = env::temp_dir().join(format!("crypthix-vector-gen-{name}-{}", process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn committed_vectors_match_the_generator() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../crypthix/v0");
    let mismatches = check(&dir);
    let report: Vec<String> = mismatches.iter().map(ToString::to_string).collect();
    assert!(mismatches.is_empty(), "{}", report.join("\n"));
}

#[test]
fn changed_missing_and_stray_files_are_reported() {
    let dir = TempDir::new("check");
    for set in sets() {
        let mut text = set.render();
        if set.file == "tv-03-cbor.json" {
            text = text.replacen("\"1805\"", "\"1806\"", 1);
        }
        if set.file != "tv-17-versions.json" {
            fs::write(dir.0.join(set.file), text).expect("write");
        }
    }
    fs::write(dir.0.join("tv-99-stray.json"), "{}\n").expect("write");
    let mismatches = check(&dir.0);
    let problems: Vec<(&str, &Problem)> = mismatches
        .iter()
        .map(|mismatch| (mismatch.file.as_str(), &mismatch.problem))
        .collect();
    assert_eq!(
        problems.len(),
        3,
        "one changed, one missing, one stray: {problems:?}"
    );
    assert!(
        matches!(problems[0], ("tv-03-cbor.json", Problem::Differs { line }) if *line > 1),
        "the changed byte is reported with its line: {problems:?}"
    );
    assert_eq!(problems[1], ("tv-17-versions.json", &Problem::Missing));
    assert_eq!(problems[2], ("tv-99-stray.json", &Problem::Unexpected));
}
