//! Pre-commit checks on the staged changes: file hygiene, secrets, formatting and lint.
//!
//! Written in Rust rather than shell so the same checks run on Linux, macOS and Windows; the
//! hook in `.githooks/pre-commit` only calls `cargo xtask pre-commit`.

use std::io::ErrorKind;
use std::path::Path;
use std::process::{Command, ExitCode};

use crate::process::{cargo, run_status};

/// Largest file that may be committed, in bytes.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Files whose change can break formatting or lint even when no `.rs` file is staged.
const RUST_CONFIG_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rustfmt.toml",
    "clippy.toml",
    "rust-toolchain.toml",
];

/// How to install the secret scanner the hook expects.
const GITLEAKS_INSTALL: &str = "go install github.com/zricethezav/gitleaks/v8@v8.30.1";

/// Runs every check and reports the first failure.
pub(crate) fn run() -> ExitCode {
    match checks() {
        Ok(()) => {
            println!("pre-commit: all checks passed");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("pre-commit: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Points git at the versioned hooks in `.githooks/`.
pub(crate) fn install() -> ExitCode {
    match git(&["config", "core.hooksPath", ".githooks"]) {
        Ok(_) => {
            println!("git hooks enabled: core.hooksPath = .githooks");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("install-hooks: {message}");
            ExitCode::FAILURE
        }
    }
}

fn checks() -> Result<(), String> {
    let staged = staged_paths()?;
    if staged.is_empty() {
        return Ok(());
    }

    step("file hygiene");
    hygiene(&staged)?;

    step("secrets (gitleaks)");
    secrets()?;

    let rust_files: Vec<&str> = staged
        .iter()
        .map(String::as_str)
        .filter(|path| {
            Path::new(path)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
        })
        .collect();
    let config_changed = staged.iter().any(|path| {
        let name = Path::new(path).file_name().and_then(|name| name.to_str());
        name.is_some_and(|name| RUST_CONFIG_FILES.contains(&name))
    });
    if rust_files.is_empty() && !config_changed {
        return Ok(());
    }

    step("formatting (cargo fmt)");
    run_status(
        Command::new(cargo()).args(["fmt", "--all", "--check"]),
        "run `cargo fmt --all` and stage the result",
    )?;
    // `cargo fmt` only sees files reachable from a crate root; check staged files directly too.
    if !rust_files.is_empty() {
        run_status(
            Command::new("rustfmt")
                .args(["--check", "--edition", "2024", "--"])
                .args(&rust_files),
            "run `rustfmt --edition 2024` on the files above and stage the result",
        )?;
    }

    step("lint (cargo clippy)");
    run_status(
        Command::new(cargo()).args([
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--quiet",
            "--",
            "-D",
            "warnings",
        ]),
        "clippy found problems (see above)",
    )?;

    // `tests/` is its own workspace, built on crypthix-types, so a change to either can break
    // it. The cargo-fuzz crate is left out: libFuzzer needs a C++ compiler even to check, and
    // its binaries only call the harness.
    let side_changed = staged
        .iter()
        .any(|path| path.starts_with("tests/") || path.starts_with("crates/foundation/types/"));
    if !side_changed {
        return Ok(());
    }
    step("lint (cargo clippy, tests/ workspace)");
    run_status(
        Command::new(cargo()).args([
            "clippy",
            "--manifest-path",
            "tests/Cargo.toml",
            "--package",
            "crypthix-fuzz-harness",
            "--package",
            "crypthix-vector-gen",
            "--all-targets",
            "--locked",
            "--quiet",
            "--",
            "-D",
            "warnings",
        ]),
        "clippy found problems in tests/ (see above)",
    )?;
    // The vector check, schema and fuzz replay: a parser change must still pass them.
    step("tests (tests/ workspace)");
    run_status(
        Command::new(cargo()).args([
            "test",
            "--manifest-path",
            "tests/Cargo.toml",
            "--locked",
            "--quiet",
        ]),
        "tests in tests/ failed (see above)",
    )
}

/// Paths of staged files that were added, copied, modified or renamed.
fn staged_paths() -> Result<Vec<String>, String> {
    let output = git(&[
        "diff",
        "--cached",
        "--name-only",
        "--diff-filter=ACMR",
        "-z",
    ])?;
    split_nul(&output)
        .map(|path| {
            String::from_utf8(path.to_vec()).map_err(|_| "a staged path is not UTF-8".to_owned())
        })
        .collect()
}

/// Whitespace errors, conflict markers, file size and a final newline.
fn hygiene(staged: &[String]) -> Result<(), String> {
    // Trailing whitespace, blank lines at the end of a file and leftover conflict markers.
    run_status(
        Command::new("git").args(["diff", "--cached", "--check"]),
        "whitespace errors or conflict markers (see above)",
    )?;
    let binary = binary_paths()?;
    let as_published = unconverted_paths(staged)?;
    for path in staged {
        let spec = format!(":{path}");
        let size_text = git(&["cat-file", "-s", &spec])?;
        let size: u64 = String::from_utf8_lossy(&size_text)
            .trim()
            .parse()
            .map_err(|_| format!("cannot read the size of {path}"))?;
        if size > MAX_FILE_BYTES {
            return Err(format!(
                "{path} is {size} bytes, over the {MAX_FILE_BYTES}-byte limit"
            ));
        }
        if size > 0 && !binary.contains(path) && !as_published.contains(path) {
            let content = git(&["cat-file", "blob", &spec])?;
            if content.last() != Some(&b'\n') {
                return Err(format!("{path} does not end with a newline"));
            }
        }
    }
    Ok(())
}

/// Staged paths that git treats as binary.
fn binary_paths() -> Result<Vec<String>, String> {
    // With -z, each record is "added<TAB>deleted<TAB>path"; binary files show "-" counts.
    let output = git(&["diff", "--cached", "--numstat", "-z", "--diff-filter=ACMR"])?;
    let mut binary = Vec::new();
    for record in split_nul(&output) {
        let record = String::from_utf8_lossy(record);
        let mut fields = record.splitn(3, '\t');
        if let (Some("-"), Some(_), Some(path)) = (fields.next(), fields.next(), fields.next()) {
            binary.push(path.to_owned());
        }
    }
    Ok(binary)
}

/// Staged paths whose `text` attribute is unset in `.gitattributes`: vendored files kept
/// exactly as published, which may lack a final newline.
fn unconverted_paths(staged: &[String]) -> Result<Vec<String>, String> {
    let mut args = vec!["check-attr", "--cached", "-z", "text", "--"];
    args.extend(staged.iter().map(String::as_str));
    // With -z, each record is "path NUL attribute NUL value NUL".
    let output = git(&args)?;
    let fields: Vec<&[u8]> = output.split(|byte| *byte == 0).collect();
    let (records, _) = fields.as_chunks::<3>();
    Ok(records
        .iter()
        .filter(|[_, _, value]| *value == b"unset")
        .map(|[path, _, _]| String::from_utf8_lossy(path).into_owned())
        .collect())
}

/// Scans the staged changes for secrets with gitleaks.
fn secrets() -> Result<(), String> {
    match Command::new("gitleaks").arg("version").output() {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(format!("gitleaks is not installed: {GITLEAKS_INSTALL}"));
        }
        Err(error) => return Err(format!("cannot run gitleaks: {error}")),
    }
    run_status(
        Command::new("gitleaks").args([
            "git",
            "--pre-commit",
            "--staged",
            "--redact",
            "--no-banner",
            "--log-level",
            "warn",
        ]),
        "gitleaks found a possible secret (see above)",
    )
}

fn step(name: &str) {
    println!("pre-commit: {name}");
}

/// Runs `git` with `args` and returns its standard output.
fn git(args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .args(args)
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// The non-empty NUL-separated records of `output`.
fn split_nul(output: &[u8]) -> impl Iterator<Item = &[u8]> {
    output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
}
