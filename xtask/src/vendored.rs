//! `cargo xtask check-vendored`: the vendored test vectors are the bytes their SOURCE records.
//!
//! Each folder under `tests/test-vectors/external/` has a SOURCE file whose `blobs:` section
//! lists the git blob ID of every other file there. For files copied from upstream the ID equals
//! upstream's blob at the pinned commit, so anyone can check it against the upstream repository
//! without trusting this one. Git's object IDs avoid a hashing crate, which only
//! `crypthix-crypto` may use.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use crate::pre_commit::git;
use crate::process::repo_root;

/// Where the vendored vectors live, relative to the repository root.
const EXTERNAL: &str = "tests/test-vectors/external";

/// Checks every vendored folder against its SOURCE.
pub(crate) fn check() -> Result<(), String> {
    let root = repo_root().join(EXTERNAL);
    let mut problems = Vec::new();
    let mut folders = 0;
    let entries =
        fs::read_dir(&root).map_err(|error| format!("cannot read {EXTERNAL}: {error}"))?;
    let mut dirs: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        folders += 1;
        check_folder(&dir, &mut problems)?;
    }
    if problems.is_empty() {
        println!("vendored vectors: {folders} folders match their SOURCE blob IDs");
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("vendored vectors: {problem}");
        }
        Err(format!("{} vendored-vector problems", problems.len()))
    }
}

fn check_folder(dir: &Path, problems: &mut Vec<String>) -> Result<(), String> {
    let name = dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let source = fs::read_to_string(dir.join("SOURCE"))
        .map_err(|error| format!("cannot read {name}/SOURCE: {error}"))?;
    let mut recorded = match parse_blobs(&source) {
        Ok(recorded) => recorded,
        Err(problem) => {
            problems.push(format!("{name}/SOURCE: {problem}"));
            return Ok(());
        }
    };
    let mut files: Vec<String> = fs::read_dir(dir)
        .map_err(|error| format!("cannot read {name}: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|file| file != "SOURCE")
        .collect();
    files.sort();
    for file in files {
        let Some(expected) = recorded.remove(&file) else {
            problems.push(format!("{name}/{file} has no blob ID in SOURCE"));
            continue;
        };
        let path = dir.join(&file);
        let output = git(&[
            OsStr::new("hash-object"),
            OsStr::new("--"),
            path.as_os_str(),
        ])?;
        let actual = String::from_utf8_lossy(&output).trim().to_owned();
        if actual != expected {
            problems.push(format!(
                "{name}/{file} is blob {actual}, but SOURCE records {expected}"
            ));
        }
    }
    for file in recorded.keys() {
        problems.push(format!("{name}/SOURCE lists {file}, which is missing"));
    }
    Ok(())
}

/// The `blobs:` section of a SOURCE file: indented `<40 hex>  <file>` lines after the header.
fn parse_blobs(source: &str) -> Result<BTreeMap<String, String>, String> {
    let mut lines = source
        .lines()
        .skip_while(|line| !line.starts_with("blobs:"));
    if lines.next().is_none() {
        return Err("no blobs: section".to_owned());
    }
    let mut blobs = BTreeMap::new();
    for line in lines {
        let Some(entry) = line.strip_prefix("  ") else {
            break;
        };
        let entry = entry.trim_start();
        let Some((id, file)) = entry.split_once("  ") else {
            continue;
        };
        if id.len() != 40 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            // The wrapped description line after `blobs:`.
            continue;
        }
        if blobs
            .insert(file.trim().to_owned(), id.to_owned())
            .is_some()
        {
            return Err(format!("{file} is listed twice"));
        }
    }
    if blobs.is_empty() {
        return Err("the blobs: section lists no files".to_owned());
    }
    Ok(blobs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "3f991dd56496129e3a99b6b486408ef8f3df6945";

    #[test]
    fn reads_the_blob_lines_after_the_header() {
        let source = format!(
            "x\nfiles:\n  a -> a\nblobs:      ids; checked\n            by xtask\n  {ID}  a.json\n"
        );
        let blobs = parse_blobs(&source).expect("valid section");
        assert_eq!(
            blobs.get("a.json").map(String::as_str),
            Some(ID),
            "{blobs:?}"
        );
        assert_eq!(
            blobs.len(),
            1,
            "the description line is not a blob: {blobs:?}"
        );
    }

    #[test]
    fn a_missing_or_empty_section_is_an_error() {
        assert!(parse_blobs("files:\n  a -> a\n").is_err(), "no section");
        assert!(parse_blobs("blobs:      none\n").is_err(), "no entries");
    }

    #[test]
    fn a_file_listed_twice_is_an_error() {
        let source = format!("blobs:\n  {ID}  a\n  {ID}  a\n");
        assert!(parse_blobs(&source).is_err(), "duplicate entry accepted");
    }

    #[test]
    fn the_committed_vectors_match() {
        assert_eq!(
            check(),
            Ok(()),
            "tests/test-vectors/external is out of step"
        );
    }
}
