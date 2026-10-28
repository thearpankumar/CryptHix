//! Repository automation: architecture layer checks and git hooks.
//!
//! - `cargo xtask check-layers` checks crate dependencies against the layer rules.
//! - `cargo xtask pre-commit` runs the pre-commit checks on the staged changes.
//! - `cargo xtask install-hooks` enables the hooks in `.githooks/` for this clone.

// Printing a report is this tool's job; the print lints target library code.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod layers;
mod pre_commit;

use std::collections::HashMap;
use std::env;
use std::process::ExitCode;

use cargo_metadata::{DependencyKind, MetadataCommand};

use crate::layers::Placement;

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("check-layers") => check_layers(),
        Some("pre-commit") => pre_commit::run(),
        Some("install-hooks") => pre_commit::install(),
        _ => {
            eprintln!("usage: cargo xtask <check-layers | pre-commit | install-hooks>");
            ExitCode::FAILURE
        }
    }
}

/// Checks every dependency between workspace packages against the layer rules.
fn check_layers() -> ExitCode {
    let metadata = match MetadataCommand::new().no_deps().exec() {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("cargo metadata failed: {error}");
            return ExitCode::FAILURE;
        }
    };

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
        ExitCode::SUCCESS
    } else {
        for problem in &problems {
            eprintln!("layer rule violation: {problem}");
        }
        ExitCode::FAILURE
    }
}
