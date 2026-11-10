//! Commands for the `tests/` workspace: test vectors, stable fuzz replay and fuzzing.
//!
//! `tests/` is its own Cargo workspace (see `tests/Cargo.toml`), so these commands point cargo
//! at its manifest instead of being part of `cargo test --workspace`.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::process::{cargo, repo_root, require_tool, run_status};

/// A fuzz target in `tests/fuzz/fuzz_targets`, with the dictionary it uses and the longest input
/// libFuzzer may make for it.
#[derive(Clone, Copy, Debug)]
struct FuzzTarget {
    name: &'static str,
    dictionary: Option<&'static str>,
    /// libFuzzer's `-max_len`. It also truncates longer corpus files, so it must hold the
    /// largest seed the vectors give the target; `run_fuzz` fails if one is longer.
    max_len: usize,
}

/// `-max_len` for targets whose inputs are short: small inputs keep the fuzzer fast.
const DEFAULT_MAX_LEN: usize = 4096;

/// Every fuzz target; a test checks this against `tests/fuzz/fuzz_targets`.
const FUZZ_TARGETS: [FuzzTarget; 13] = [
    FuzzTarget {
        name: "preamble",
        dictionary: None,
        // The keyring vectors at their 4096-byte body cap, with the preamble before it.
        max_len: 8 * 1024,
    },
    FuzzTarget {
        name: "cbor_document",
        dictionary: Some("cbor.dict"),
        max_len: DEFAULT_MAX_LEN,
    },
    FuzzTarget {
        name: "cbor_differential",
        dictionary: Some("cbor.dict"),
        max_len: DEFAULT_MAX_LEN,
    },
    FuzzTarget {
        name: "cbor_structured",
        dictionary: None,
        max_len: DEFAULT_MAX_LEN,
    },
    FuzzTarget {
        name: "store_key",
        dictionary: None,
        max_len: DEFAULT_MAX_LEN,
    },
    FuzzTarget {
        name: "config_toml",
        dictionary: Some("toml.dict"),
        max_len: DEFAULT_MAX_LEN,
    },
    FuzzTarget {
        name: "id_text",
        dictionary: None,
        max_len: DEFAULT_MAX_LEN,
    },
    FuzzTarget {
        name: "cx_open",
        dictionary: None,
        max_len: DEFAULT_MAX_LEN,
    },
    FuzzTarget {
        name: "verifying_key",
        dictionary: None,
        max_len: DEFAULT_MAX_LEN,
    },
    FuzzTarget {
        name: "inner_plaintext",
        dictionary: Some("zstd.dict"),
        max_len: DEFAULT_MAX_LEN,
    },
    FuzzTarget {
        name: "decompress",
        dictionary: Some("zstd.dict"),
        // Frames whose 128 KiB blocks reach zstd's block edges, about 131 KB with the length
        // prefix and frame header.
        max_len: 144 * 1024,
    },
    FuzzTarget {
        name: "data_blob_open",
        dictionary: Some("zstd.dict"),
        // Data blobs of TV-07, about 5 KB.
        max_len: 8 * 1024,
    },
    FuzzTarget {
        name: "chunker",
        dictionary: None,
        max_len: DEFAULT_MAX_LEN,
    },
];

/// Seconds per target when `--time` is not given.
const DEFAULT_FUZZ_SECONDS: u64 = 60;

/// The nightly that fuzzing uses, pinned so a new nightly cannot break CI unannounced.
/// `CRYPTHIX_FUZZ_TOOLCHAIN` overrides it.
const FUZZ_TOOLCHAIN: &str = "nightly-2026-10-15";

/// How to install the fuzzing tool the `fuzz` command expects.
const CARGO_FUZZ_INSTALL: &str = "cargo install cargo-fuzz --locked";

/// How to install the licence and advisory checker `test-extra` runs on `tests/`.
const CARGO_DENY_INSTALL: &str = "cargo install cargo-deny --locked";

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

/// Checks the committed vector files match the generator.
pub(crate) fn vectors_check() -> Result<(), String> {
    run_generator(&["check"])
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
    side_tests()?;
    side_deny()
}

/// The `tests/` workspace tests: vector check, schema, external vectors and fuzz replay.
pub(crate) fn side_tests() -> Result<(), String> {
    run_status(
        Command::new(cargo())
            .arg("test")
            .arg("--manifest-path")
            .arg(tests_dir().join("Cargo.toml"))
            .arg("--locked"),
        "tests in tests/ failed (see above)",
    )
}

/// cargo-deny on the `tests/` workspace, with its own config.
pub(crate) fn side_deny() -> Result<(), String> {
    let manifest = tests_dir().join("Cargo.toml");
    require_tool(
        Command::new(cargo()).arg("deny"),
        "cargo-deny",
        CARGO_DENY_INSTALL,
    )?;
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
    let toolchain =
        env::var("CRYPTHIX_FUZZ_TOOLCHAIN").unwrap_or_else(|_| FUZZ_TOOLCHAIN.to_owned());
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
    let host = toolchain_host(&toolchain)?;
    let corpus = tests_dir().join("fuzz").join("corpus");
    let corpus_arg = corpus.to_string_lossy().into_owned();
    run_generator(&["seeds", &corpus_arg])?;
    for target in targets {
        let name = target.name;
        check_seed_lengths(target, &corpus.join(name))?;
        println!("fuzz: {name} for {seconds} s");
        // libFuzzer refuses a corpus directory that does not exist, and structure-aware targets
        // get no seeds from the vectors.
        fs::create_dir_all(corpus.join(name))
            .map_err(|error| format!("cannot create the {name} corpus: {error}"))?;
        let mut command = toolchain_cargo(&toolchain);
        // -O -a: optimised, but keeping debug assertions and overflow checks, so wrapping
        // length arithmetic panics (T-39). The regressions directory is a second, read-only
        // corpus; libFuzzer writes new inputs only to the first. The malloc limit catches a
        // parser that allocates for a declared length before checking it (FS-11). The target is
        // the toolchain's host: cargo-fuzz otherwise builds for the triple it was itself built
        // for, and its prebuilt Linux release is musl, where the address sanitizer cannot run.
        command
            .current_dir(tests_dir())
            .args([
                "fuzz",
                "run",
                "--fuzz-dir",
                "fuzz",
                "-O",
                "-a",
                "--target",
                &host,
                name,
            ])
            .arg(corpus.join(name))
            .arg(tests_dir().join("fuzz").join("regressions").join(name))
            .arg("--")
            .arg(format!("-max_total_time={seconds}"))
            .arg(format!("-max_len={}", target.max_len))
            .args(["-timeout=10", "-rss_limit_mb=2048", "-malloc_limit_mb=64"]);
        if let Some(dictionary) = target.dictionary {
            let path = tests_dir().join("fuzz").join("dicts").join(dictionary);
            let mut flag = OsString::from("-dict=");
            flag.push(path);
            command.arg(flag);
        }
        run_status(
            &mut command,
            &format!(
                "fuzz target {name} failed (see above). If it found a crash, the input is in \
                 tests/fuzz/artifacts/{name}/: minimise it with `cd tests && cargo +{toolchain} \
                 fuzz tmin --fuzz-dir fuzz --target {host} {name} fuzz/artifacts/{name}/<file>` \
                 and save it under tests/fuzz/regressions/{name}/ (see tests/README.md)"
            ),
        )?;
    }
    Ok(())
}

/// Fails if a seed in `dir` is longer than the target's `max_len`, which libFuzzer would
/// silently cut short. A missing directory has no seeds.
fn check_seed_lengths(target: &FuzzTarget, dir: &Path) -> Result<(), String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot list {}: {error}", dir.display()))?;
        let len = entry
            .metadata()
            .map_err(|error| format!("cannot read {}: {error}", entry.path().display()))?
            .len();
        if usize::try_from(len).map_or(true, |len| len > target.max_len) {
            return Err(format!(
                "seed {} is {len} bytes, over the {} target's max_len of {}: libFuzzer would \
                 truncate it; raise max_len in xtask/src/side.rs",
                entry.path().display(),
                target.name,
                target.max_len
            ));
        }
    }
    Ok(())
}

/// The host triple of `toolchain`, from `rustc -vV`.
fn toolchain_host(toolchain: &str) -> Result<String, String> {
    let output = Command::new("rustup")
        .args(["run", toolchain, "rustc", "-vV"])
        .output()
        .map_err(|error| format!("cannot run rustup: {error}"))?;
    if !output.status.success() {
        return Err(format!("`rustup run {toolchain} rustc -vV` failed"));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| format!("`rustc -vV` of {toolchain} names no host"))
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

    #[test]
    fn a_seed_over_max_len_fails_the_run() {
        let dir = env::temp_dir().join(format!("xtask-seed-lengths-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temporary directory");
        let target = FuzzTarget {
            name: "test",
            dictionary: None,
            max_len: 8,
        };
        fs::write(dir.join("short"), [0; 8]).expect("seed written");
        let fits = check_seed_lengths(&target, &dir);
        fs::write(dir.join("long"), [0; 9]).expect("seed written");
        let over = check_seed_lengths(&target, &dir);
        fs::remove_dir_all(&dir).expect("temporary directory removed");
        assert_eq!(fits, Ok(()));
        let error = over.expect_err("a 9-byte seed passed max_len 8");
        assert!(error.contains("9 bytes"), "{error}");
        assert_eq!(
            check_seed_lengths(&target, &dir),
            Ok(()),
            "a missing corpus has no seeds"
        );
    }
}
