//! Commands for the `tests/` workspace: test vectors, stable fuzz replay and fuzzing.
//!
//! `tests/` is its own Cargo workspace (see `tests/Cargo.toml`), so these commands point cargo
//! at its manifest instead of being part of `cargo test --workspace`.

use std::env;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::process::{cargo, run_status};

/// A fuzz target in `tests/fuzz/fuzz_targets`, with the dictionary it uses.
#[derive(Clone, Copy, Debug)]
struct FuzzTarget {
    name: &'static str,
    dictionary: Option<&'static str>,
}

/// Every fuzz target; a test checks this against `tests/fuzz/fuzz_targets`.
const FUZZ_TARGETS: [FuzzTarget; 7] = [
    FuzzTarget {
        name: "preamble",
        dictionary: None,
    },
    FuzzTarget {
        name: "cbor_document",
        dictionary: Some("cbor.dict"),
    },
    FuzzTarget {
        name: "cbor_differential",
        dictionary: Some("cbor.dict"),
    },
    FuzzTarget {
        name: "cbor_structured",
        dictionary: None,
    },
    FuzzTarget {
        name: "store_key",
        dictionary: None,
    },
    FuzzTarget {
        name: "config_toml",
        dictionary: Some("toml.dict"),
    },
    FuzzTarget {
        name: "id_text",
        dictionary: None,
    },
];

/// Seconds per target when `--time` is not given.
const DEFAULT_FUZZ_SECONDS: u64 = 60;

/// How to install the fuzzing tool the `fuzz` command expects.
const CARGO_FUZZ_INSTALL: &str = "cargo install cargo-fuzz --locked";

/// How to install the licence and advisory checker `test-extra` runs on `tests/`.
const CARGO_DENY_INSTALL: &str = "cargo install cargo-deny --locked";

/// The repository root: xtask lives in `<root>/xtask`.
fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent().unwrap_or(manifest_dir).to_path_buf()
}

fn tests_dir() -> PathBuf {
    repo_root().join("tests")
}

/// `cargo xtask vectors [--check]`: rewrite the vector files, or check they are current.
pub(crate) fn vectors(args: &[String]) -> ExitCode {
    let mode = match args {
        [] => "write",
        [flag] if flag == "--check" => "check",
        _ => return usage("cargo xtask vectors [--check]"),
    };
    report(run_generator(&[mode]))
}

/// `cargo xtask test-extra`: the `tests/` workspace tests on stable (vector check, schema,
/// external vectors, fuzz replay), then cargo-deny on its dependencies.
pub(crate) fn test_extra(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        return usage("cargo xtask test-extra");
    }
    report(run_test_extra())
}

fn run_test_extra() -> Result<(), String> {
    let manifest = tests_dir().join("Cargo.toml");
    run_status(
        Command::new(cargo())
            .arg("test")
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--locked"),
        "tests in tests/ failed (see above)",
    )?;
    match Command::new(cargo()).args(["deny", "--version"]).output() {
        Ok(output) if output.status.success() => {}
        _ => return Err(format!("cargo-deny is not installed: {CARGO_DENY_INSTALL}")),
    }
    run_status(
        Command::new(cargo())
            .arg("deny")
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--config")
            .arg(tests_dir().join("deny.toml"))
            .arg("check"),
        "cargo deny found problems in tests/ (see above)",
    )
}

/// `cargo xtask fuzz <target | all> [--time <seconds>]`: fuzz on nightly, starting from the
/// vector inputs.
pub(crate) fn fuzz(args: &[String]) -> ExitCode {
    let usage_text = "cargo xtask fuzz <target | all> [--time <seconds>]";
    let (target, seconds) = match args {
        [target] => (target.as_str(), DEFAULT_FUZZ_SECONDS),
        [target, flag, value] if flag == "--time" => {
            // libFuzzer reads -max_total_time=0 as "no limit".
            let seconds: u64 = match value.parse() {
                Ok(seconds) if seconds > 0 => seconds,
                _ => return usage(usage_text),
            };
            (target.as_str(), seconds)
        }
        _ => return usage(usage_text),
    };
    let targets: Vec<FuzzTarget> = if target == "all" {
        FUZZ_TARGETS.to_vec()
    } else if let Some(known) = FUZZ_TARGETS.iter().find(|known| known.name == target) {
        vec![*known]
    } else {
        let names: Vec<&str> = FUZZ_TARGETS.iter().map(|known| known.name).collect();
        eprintln!(
            "fuzz: unknown target {target}; targets: {}",
            names.join(", ")
        );
        return ExitCode::FAILURE;
    };
    report(run_fuzz(&targets, seconds))
}

fn run_fuzz(targets: &[FuzzTarget], seconds: u64) -> Result<(), String> {
    let toolchain = env::var("CRYPTHIX_FUZZ_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_owned());
    match toolchain_cargo(&toolchain)
        .args(["fuzz", "--version"])
        .output()
    {
        Ok(output) if output.status.success() => {}
        Ok(_) => {
            return Err(format!(
                "cargo-fuzz or the {toolchain} toolchain is missing: {CARGO_FUZZ_INSTALL}, \
                 rustup toolchain install {toolchain}"
            ));
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err("rustup is not on PATH; fuzzing needs a rustup-managed nightly".to_owned());
        }
        Err(error) => return Err(format!("cannot run rustup: {error}")),
    }
    let corpus = tests_dir().join("fuzz").join("corpus");
    let corpus_arg = corpus.to_string_lossy().into_owned();
    run_generator(&["seeds", &corpus_arg])?;
    for target in targets {
        let name = target.name;
        println!("fuzz: {name} for {seconds} s");
        let mut command = toolchain_cargo(&toolchain);
        // -O -a: optimised, but keeping debug assertions and overflow checks, so wrapping
        // length arithmetic panics (T-39). The regressions directory is a second, read-only
        // corpus; libFuzzer writes new inputs only to the first. The malloc limit catches a
        // parser that allocates for a declared length before checking it (FS-11).
        command
            .current_dir(tests_dir())
            .args(["fuzz", "run", "--fuzz-dir", "fuzz", "-O", "-a", name])
            .arg(corpus.join(name))
            .arg(tests_dir().join("fuzz").join("regressions").join(name))
            .arg("--")
            .arg(format!("-max_total_time={seconds}"))
            .args([
                "-max_len=4096",
                "-timeout=10",
                "-rss_limit_mb=2048",
                "-malloc_limit_mb=64",
            ]);
        if let Some(dictionary) = target.dictionary {
            let path = tests_dir().join("fuzz").join("dicts").join(dictionary);
            let mut flag = OsString::from("-dict=");
            flag.push(path);
            command.arg(flag);
        }
        run_status(
            &mut command,
            &format!(
                "fuzz target {name} failed; the input is in tests/fuzz/artifacts/{name}/. \
                 Minimise it with `cd tests && cargo +{toolchain} fuzz tmin --fuzz-dir fuzz \
                 {name} fuzz/artifacts/{name}/<file>` and save it under \
                 tests/fuzz/regressions/{name}/ (see tests/README.md)"
            ),
        )?;
    }
    Ok(())
}

/// Runs the vector generator with `args`.
fn run_generator(args: &[&str]) -> Result<(), String> {
    run_status(
        Command::new(cargo())
            .arg("run")
            .arg("--quiet")
            .arg("--locked")
            .arg("--manifest-path")
            .arg(tests_dir().join("Cargo.toml"))
            .args(["--package", "crypthix-vector-gen", "--"])
            .args(args),
        "the vector generator failed (see above)",
    )
}

/// `cargo` from `toolchain`, through `rustup run` rather than the `+toolchain` shorthand, which
/// fails when PATH puts a toolchain's own cargo before the rustup proxy (as on some Windows
/// setups). The variables that would pin the child to xtask's toolchain are removed.
fn toolchain_cargo(toolchain: &str) -> Command {
    let mut command = Command::new("rustup");
    command
        .args(["run", toolchain, "cargo"])
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC");
    command
}

fn report(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

fn usage(text: &str) -> ExitCode {
    eprintln!("usage: {text}");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    #[test]
    fn fuzz_targets_match_the_fuzz_binaries() {
        let dir = tests_dir().join("fuzz").join("fuzz_targets");
        let mut on_disk: Vec<String> = fs::read_dir(&dir)
            .expect("tests/fuzz/fuzz_targets exists")
            .map(|entry| entry.expect("readable entry").path())
            .filter_map(|path| {
                path.file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
            })
            .collect();
        on_disk.sort();
        let mut listed: Vec<String> = FUZZ_TARGETS
            .iter()
            .map(|target| target.name.to_owned())
            .collect();
        listed.sort();
        assert_eq!(listed, on_disk, "FUZZ_TARGETS must list every fuzz binary");
    }
}
