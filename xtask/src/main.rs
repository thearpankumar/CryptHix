//! Repository automation: architecture layer checks.
//!
//! Run with `cargo xtask check-layers`.

// Printing a report is this tool's job; the print lints target library code.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod layers;

use std::collections::HashMap;
use std::env;
use std::process::ExitCode;

use cargo_metadata::{DependencyKind, MetadataCommand};

use crate::layers::Placement;

fn main() -> ExitCode {
    if env::args().nth(1).as_deref() == Some("check-layers") {
        check_layers()
    } else {
        eprintln!("usage: cargo xtask check-layers");
        ExitCode::FAILURE
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
