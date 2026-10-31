//! `cargo xtask check-features`: no release build may enable the test-only features of
//! `crypthix-crypto` (FS-01, FS-94).
//!
//! `test-rng` is the seeded stream of the vector generator and `vectors` exposes the inner
//! CX-AEAD errors and raw entry points. Only the `tests/` workspace and the crate's own tests use
//! them. A release build could still pick one up:
//!
//! - through a normal or build dependency that names it, under any name the dependency is
//!   renamed to;
//! - through a package feature that forwards to it, or to another `crypthix-crypto` feature that
//!   enables it;
//! - through `crypthix-crypto`'s own default features.
//!
//! The first two are read from `cargo metadata`. Then `cargo tree`, without dev-dependencies,
//! resolves the whole workspace with default features, and every package that depends on the
//! crate with `--all-features` on every target, and must show neither feature. Any failure to
//! run or read `cargo tree` fails the check.
//!
//! Compiler flags can do the same behind Cargo's back: `--cfg feature="vectors"` turns a feature
//! on, and `--cfg getrandom_backend=...` replaces the kernel source of every key and nonce
//! (FS-01). The check rejects either in `RUSTFLAGS` and in the repository's Cargo config files.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::process::Command;

use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, Package, PackageId};

use crate::process::{cargo, repo_root};

/// The crate whose features are guarded.
const CRATE: &str = "crypthix-crypto";

/// Its features that a release build must never enable.
const TEST_ONLY: [&str; 2] = ["test-rng", "vectors"];

/// Runs the check on the main workspace.
pub(crate) fn check() -> Result<(), String> {
    let metadata = MetadataCommand::new()
        .exec()
        .map_err(|error| format!("cargo metadata failed: {error}"))?;
    let crypto = metadata
        .workspace_packages()
        .into_iter()
        .find(|package| package.name.as_str() == CRATE)
        .ok_or_else(|| format!("{CRATE} is not a workspace member"))?;
    let guarded = guarded_features(&crypto.features);

    let mut problems = Vec::new();
    for package in metadata.workspace_packages() {
        problems.extend(manifest_problems(package, &guarded));
    }
    problems.extend(
        flag_sources()
            .iter()
            .flat_map(|(source, text)| flag_problems(source, text)),
    );
    problems.extend(resolved_problems(&["--workspace"], &guarded)?);
    for package in dependents(&metadata, &crypto.id) {
        let args = ["--package", package, "--all-features", "--target", "all"];
        problems.extend(resolved_problems(&args, &guarded)?);
    }

    if problems.is_empty() {
        println!(
            "features: no release build enables {}",
            TEST_ONLY.join(" or ")
        );
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("feature rule violation: {problem}");
        }
        Err(format!(
            "{} release builds must not enable test-only features of {CRATE} (FS-01)",
            problems.len()
        ))
    }
}

/// The test-only features and every feature of the crate that turns one of them on, directly or
/// through other features.
fn guarded_features(
    features: &std::collections::BTreeMap<String, Vec<String>>,
) -> BTreeSet<String> {
    let mut guarded: BTreeSet<String> = TEST_ONLY
        .iter()
        .map(|feature| (*feature).to_owned())
        .collect();
    loop {
        let more: Vec<String> = features
            .iter()
            .filter(|(name, enables)| {
                !guarded.contains(*name) && enables.iter().any(|value| guarded.contains(value))
            })
            .map(|(name, _)| name.clone())
            .collect();
        if more.is_empty() {
            return guarded;
        }
        guarded.extend(more);
    }
}

/// Problems in one package's manifest: dependencies on the crate that turn on a guarded feature
/// outside dev-dependencies, and package features that forward to one.
fn manifest_problems(package: &Package, guarded: &BTreeSet<String>) -> Vec<String> {
    let mut problems = Vec::new();
    // The names this package refers to the crate by: its own name, or a rename.
    let mut aliases = BTreeSet::new();
    for dependency in &package.dependencies {
        if dependency.name != CRATE {
            continue;
        }
        let alias = dependency
            .rename
            .clone()
            .unwrap_or_else(|| CRATE.to_owned());
        problems.extend(dependency_problem(
            &package.name,
            &alias,
            dependency.kind,
            &dependency.features,
            guarded,
        ));
        aliases.insert(alias);
    }
    if package.name.as_str() == CRATE {
        aliases.insert(CRATE.to_owned());
    }
    for (feature, enables) in &package.features {
        problems.extend(forwarding_problems(
            &package.name,
            feature,
            enables,
            &aliases,
            guarded,
        ));
    }
    problems
}

/// A normal or build dependency on the crate that turns on a guarded feature. Dev-dependencies
/// are fine: they never reach a release build.
fn dependency_problem(
    package: &str,
    alias: &str,
    kind: DependencyKind,
    features: &[String],
    guarded: &BTreeSet<String>,
) -> Option<String> {
    if kind == DependencyKind::Development {
        return None;
    }
    let enabled: Vec<&str> = features
        .iter()
        .map(String::as_str)
        .filter(|feature| guarded.contains(*feature))
        .collect();
    (!enabled.is_empty()).then(|| {
        format!(
            "{package} depends on {CRATE} (as `{alias}`) with {} outside dev-dependencies",
            enabled.join(", ")
        )
    })
}

/// Package features that enable a guarded feature: `debug = ["crypthix-crypto/test-rng"]`,
/// the same through a renamed dependency or `?/`, or, in the crate itself, a default feature.
fn forwarding_problems(
    package: &str,
    feature: &str,
    enables: &[String],
    aliases: &BTreeSet<String>,
    guarded: &BTreeSet<String>,
) -> Vec<String> {
    enables
        .iter()
        .filter_map(|value| {
            let forwarded = value.split_once('/').and_then(|(dependency, target)| {
                let dependency = dependency.strip_suffix('?').unwrap_or(dependency);
                (aliases.contains(dependency) && guarded.contains(target)).then_some(target)
            });
            let defaulted = (package == CRATE && feature == "default" && guarded.contains(value))
                .then_some(value.as_str());
            forwarded
                .or(defaulted)
                .map(|name| format!("{package} feature `{feature}` enables {CRATE}/{name}"))
        })
        .collect()
}

/// The workspace packages other than the crate that reach it through normal or build
/// dependencies, so `--all-features` on them could reach its features.
fn dependents<'a>(metadata: &'a Metadata, crypto: &PackageId) -> Vec<&'a str> {
    let Some(resolve) = &metadata.resolve else {
        return Vec::new();
    };
    let edges: HashMap<&PackageId, Vec<&PackageId>> = resolve
        .nodes
        .iter()
        .map(|node| {
            let deps = node
                .deps
                .iter()
                .filter(|dep| {
                    dep.dep_kinds
                        .iter()
                        .any(|kind| kind.kind != DependencyKind::Development)
                })
                .map(|dep| &dep.pkg)
                .collect();
            (&node.id, deps)
        })
        .collect();
    metadata
        .workspace_packages()
        .into_iter()
        .filter(|package| package.id != *crypto && reaches(&edges, &package.id, crypto))
        .map(|package| package.name.as_str())
        .collect()
}

/// Whether `target` is reachable from `start` along `edges`.
fn reaches(
    edges: &HashMap<&PackageId, Vec<&PackageId>>,
    start: &PackageId,
    target: &PackageId,
) -> bool {
    let mut seen: HashSet<&PackageId> = HashSet::new();
    let mut stack = vec![start];
    while let Some(id) = stack.pop() {
        if id == target {
            return true;
        }
        if seen.insert(id) {
            stack.extend(edges.get(id).into_iter().flatten().copied());
        }
    }
    false
}

/// Asks `cargo tree`, without dev-dependencies, which features of the crate a build with `args`
/// resolves.
fn resolved_problems(args: &[&str], guarded: &BTreeSet<String>) -> Result<Vec<String>, String> {
    let output = Command::new(cargo())
        .args(["tree", "--locked", "--edges", "no-dev"])
        .args(args)
        .args([
            "--invert", CRATE, "--depth", "0", "--prefix", "none", "--format", "{p}|{f}",
        ])
        .output()
        .map_err(|error| format!("cannot run cargo tree: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    resolved_in(&String::from_utf8_lossy(&output.stdout), guarded)
        .map_err(|message| format!("cargo tree {}: {message}", args.join(" ")))
}

/// The compiler-flag settings a build reads: the `RUSTFLAGS` variables and the Cargo config files
/// of both workspaces, as `(source, text)`.
fn flag_sources() -> Vec<(String, String)> {
    let variables = [
        "RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
    ];
    let from_env = variables
        .iter()
        .filter_map(|name| env::var(name).ok().map(|value| ((*name).to_owned(), value)));
    let root = repo_root();
    let files = [
        ".cargo/config.toml",
        ".cargo/config",
        "tests/.cargo/config.toml",
        "tests/.cargo/config",
    ];
    let from_files = files.iter().filter_map(|file| {
        fs::read_to_string(root.join(file))
            .ok()
            .map(|text| ((*file).to_owned(), text))
    });
    from_env.chain(from_files).collect()
}

/// Flags that turn on a feature or replace the `getrandom` backend.
fn flag_problems(source: &str, text: &str) -> Vec<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let mut problems = Vec::new();
    if compact.contains("getrandom_backend") {
        problems.push(format!(
            "{source} sets getrandom_backend, replacing the kernel RNG (FS-01)"
        ));
    }
    if compact.contains("feature=") {
        problems.push(format!(
            "{source} sets a `--cfg feature=` flag, bypassing Cargo features"
        ));
    }
    problems
}

/// The guarded features in `cargo tree` lines of the form `<package> <version> (<path>)|<f,..>`.
///
/// # Errors
///
/// If no line names the crate, so a changed output format cannot pass silently.
fn resolved_in(tree: &str, guarded: &BTreeSet<String>) -> Result<Vec<String>, String> {
    let lines: Vec<(&str, &str)> = tree
        .lines()
        .filter_map(|line| line.split_once('|'))
        .filter(|(package, _)| package.starts_with(&format!("{CRATE} v")))
        .collect();
    if lines.is_empty() {
        return Err(format!("no line for {CRATE} in its output"));
    }
    Ok(lines
        .iter()
        .flat_map(|(_, features)| features.split(','))
        .filter(|feature| guarded.contains(*feature))
        .map(|feature| format!("a release build resolves {CRATE}/{feature}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn guarded() -> BTreeSet<String> {
        set(&TEST_ONLY)
    }

    #[test]
    fn features_that_enable_a_test_feature_are_guarded_too() {
        let features = BTreeMap::from([
            ("test-rng".to_owned(), strings(&["dep:chacha20"])),
            ("vectors".to_owned(), Vec::new()),
            ("bench".to_owned(), strings(&["vectors"])),
            ("deep".to_owned(), strings(&["bench"])),
            ("std".to_owned(), Vec::new()),
        ]);
        assert_eq!(
            guarded_features(&features),
            set(&["bench", "deep", "test-rng", "vectors"])
        );
    }

    #[test]
    fn normal_and_build_dependencies_may_not_enable_test_features() {
        let rng = strings(&["test-rng"]);
        let normal = dependency_problem(
            "crypthix-cli",
            CRATE,
            DependencyKind::Normal,
            &rng,
            &guarded(),
        );
        assert!(normal.is_some(), "a normal dependency enabled test-rng");
        let build = dependency_problem(
            "crypthix-cli",
            CRATE,
            DependencyKind::Build,
            &rng,
            &guarded(),
        );
        assert!(build.is_some(), "a build dependency enabled test-rng");
    }

    #[test]
    fn dev_dependencies_and_other_features_are_fine() {
        let rng = strings(&["test-rng"]);
        let dev = dependency_problem(
            "crypthix-keys",
            CRATE,
            DependencyKind::Development,
            &rng,
            &guarded(),
        );
        assert_eq!(dev, None);
        let none = dependency_problem(
            "crypthix-keys",
            CRATE,
            DependencyKind::Normal,
            &[],
            &guarded(),
        );
        assert_eq!(none, None);
    }

    #[test]
    fn forwarding_through_any_alias_is_rejected() {
        let aliases = set(&[CRATE, "cx"]);
        let enables = strings(&["crypthix-crypto/test-rng", "cx?/vectors", "cx/std", "dep:x"]);
        let problems = forwarding_problems("crypthix-cli", "debug", &enables, &aliases, &guarded());
        assert_eq!(problems.len(), 2, "{problems:?}");
        let unrelated = forwarding_problems(
            "crypthix-cli",
            "x",
            &strings(&["other/vectors"]),
            &aliases,
            &guarded(),
        );
        assert_eq!(unrelated, Vec::<String>::new());
    }

    #[test]
    fn the_crate_may_not_default_to_a_test_feature() {
        let own = set(&[CRATE]);
        let defaults =
            forwarding_problems(CRATE, "default", &strings(&["test-rng"]), &own, &guarded());
        assert_eq!(defaults.len(), 1);
        let fine = forwarding_problems(
            CRATE,
            "test-rng",
            &strings(&["dep:chacha20"]),
            &own,
            &guarded(),
        );
        assert_eq!(fine, Vec::<String>::new());
    }

    #[test]
    fn resolved_features_are_read_from_cargo_tree() {
        let clean = "crypthix-crypto v0.0.0 (/x)|\n";
        assert_eq!(resolved_in(clean, &guarded()), Ok(Vec::new()));
        let leaked = "crypthix-crypto v0.0.0 (/x)|test-rng,vectors\n";
        assert_eq!(
            resolved_in(leaked, &guarded()).map(|found| found.len()),
            Ok(2)
        );
    }

    #[test]
    fn rng_backends_and_feature_cfgs_in_flags_are_rejected() {
        let backend = flag_problems("RUSTFLAGS", "--cfg getrandom_backend=\"rdrand\"");
        assert_eq!(backend.len(), 1, "{backend:?}");
        let feature = flag_problems(
            "config",
            "rustflags = [\"--cfg\", \"feature = \\\"vectors\\\"\"]",
        );
        assert_eq!(feature.len(), 1, "{feature:?}");
        assert_eq!(
            flag_problems("config", "[alias]\nxtask = \"run\""),
            Vec::<String>::new()
        );
    }

    #[test]
    fn output_without_the_crate_fails() {
        assert!(resolved_in("", &guarded()).is_err(), "empty output passed");
        assert!(
            resolved_in("other v1.0.0|vectors\n", &guarded()).is_err(),
            "another crate passed"
        );
    }
}
