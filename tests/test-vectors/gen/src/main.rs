//! `crypthix-vector-gen write | check | seeds <dir>`; see `tests/test-vectors/README.md`.

// Printing a report is this tool's job; the print lints target library code.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crypthix_vector_gen::{check, seeds, sets};

/// `tests/test-vectors/crypthix/v0`, where the committed sets live.
fn vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../crypthix/v0")
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["write"] => write(),
        ["check"] => run_check(),
        ["seeds", dir] => write_seeds(Path::new(dir)),
        _ => Err("usage: crypthix-vector-gen <write | check | seeds <dir>>".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("crypthix-vector-gen: {message}");
            ExitCode::FAILURE
        }
    }
}

fn write() -> Result<(), String> {
    let dir = vector_dir();
    for set in sets() {
        let path = dir.join(set.file);
        fs::write(&path, set.render()).map_err(|error| format!("{}: {error}", path.display()))?;
        println!("wrote {}", set.file);
    }
    Ok(())
}

fn run_check() -> Result<(), String> {
    let mismatches = check(&vector_dir());
    if mismatches.is_empty() {
        println!("vectors: every set matches the generator");
        return Ok(());
    }
    for mismatch in &mismatches {
        eprintln!("{mismatch}");
    }
    Err(
        "committed vectors differ; run `cargo xtask vectors` and add a changelog row (FS-94)"
            .to_owned(),
    )
}

fn write_seeds(dir: &Path) -> Result<(), String> {
    let seeds = seeds();
    for seed in &seeds {
        for target in seed.target.fuzz_targets() {
            let target_dir = dir.join(target);
            fs::create_dir_all(&target_dir)
                .map_err(|error| format!("{}: {error}", target_dir.display()))?;
            let path = target_dir.join(&seed.name);
            fs::write(&path, &seed.bytes)
                .map_err(|error| format!("{}: {error}", path.display()))?;
        }
    }
    println!("wrote {} seeds to {}", seeds.len(), dir.display());
    Ok(())
}
