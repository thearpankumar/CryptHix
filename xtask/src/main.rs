//! Repository automation: architecture layer checks, git hooks and the `tests/` workspace.
//!
//! - `cargo xtask check-layers` checks crate dependencies against the layer rules.
//! - `cargo xtask check-features` checks that no release build enables a test-only feature.
//! - `cargo xtask pre-commit` runs the pre-commit checks on the staged changes.
//! - `cargo xtask install-hooks` enables the hooks in `.githooks/` for this clone.
//! - `cargo xtask vectors [--check]` rewrites the test vectors, or checks they are current.
//! - `cargo xtask test-extra` runs the `tests/` workspace tests: vectors, schema, fuzz replay.
//! - `cargo xtask fuzz <target | all> [--time <seconds>]` fuzzes on nightly.
//! - `cargo xtask ci [<job> ...] [--base <rev>]` runs the CI jobs (see `ci.rs`).
//! - `cargo xtask check-docs` checks links, anchors and cross-reference IDs in the docs.
//! - `cargo xtask check-vendored` checks the vendored vectors against their SOURCE blob IDs.
//! - `cargo xtask check-commits <base>` checks the messages of the commits after `base`.

// Printing a report is this tool's job; the print lints target library code.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod ci;
mod commits;
mod docs_check;
mod features;
mod layers;
mod pre_commit;
mod process;
mod side;
mod vendored;

use std::collections::HashMap;
use std::env;
use std::process::ExitCode;

use cargo_metadata::{DependencyKind, MetadataCommand};

use crate::layers::Placement;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (command, rest) = match args.split_first() {
        Some((command, rest)) => (command.as_str(), rest),
        None => ("", &[][..]),
    };
    match command {
        "check-layers" => report(check_layers()),
        "check-features" if rest.is_empty() => report(features::check()),
        "pre-commit" => pre_commit::run(),
        "install-hooks" => pre_commit::install(),
        "vectors" => side::vectors(rest),
        "test-extra" => side::test_extra(rest),
        "fuzz" => side::fuzz(rest),
        "ci" => report(ci::run(rest)),
        "check-docs" if rest.is_empty() => report(docs_check::check()),
        "check-vendored" if rest.is_empty() => report(vendored::check()),
        "check-commits" => match rest {
            [base] => report(commits::check(base)),
            _ => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: cargo xtask <check-layers | check-features | pre-commit | install-hooks | vectors | test-extra \
         | fuzz | ci | check-docs | check-vendored | check-commits>"
    );
    ExitCode::FAILURE
}

/// Prints a failure and turns the result into an exit code.
fn report(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Checks every dependency between workspace packages against the layer rules.
fn check_layers() -> Result<(), String> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(|error| format!("cargo metadata failed: {error}"))?;

    let mut problems: Vec<String> = Vec::new();
    let mut placements: HashMap<&str, Placement> = HashMap::new();
    for package in metadata.workspace_packages() {
        let manifest_dir = package
            .manifest_path
            .parent()
            .unwrap_or(&package.manifest_path);
        let relative_dir = manifest_dir
            .strip_prefix(&metadata.workspace_root)
            .unwrap_or(manifest_dir);
        match layers::place(&package.name, relative_dir.as_std_path()) {
            Some(placement) => {
                placements.insert(package.name.as_str(), placement);
            }
            None => problems.push(format!(
                "{} lives at {relative_dir}: crates must be in crates/<group>/<crate>, apps/ or xtask/",
                package.name
            )),
        }
    }

    for package in metadata.workspace_packages() {
        let Some(from) = placements.get(package.name.as_str()) else {
            continue;
        };
        // Dev-dependency edges are free: tests may use any crate, including crypthix-testkit.
        for dependency in &package.dependencies {
            if dependency.kind == DependencyKind::Development {
                continue;
            }
            if let Some(to) = placements.get(dependency.name.as_str())
                && let Err(violation) = layers::check_edge(from, to)
            {
                problems.push(violation.to_string());
            }
        }
    }

    if problems.is_empty() {
        println!("layer rules: {} packages, no violations", placements.len());
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("layer rule violation: {problem}");
        }
        Err(format!("{} layer rule violations", problems.len()))
    }
}
