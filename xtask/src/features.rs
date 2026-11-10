//! `cargo xtask check-features`: no release build may enable the test-only features of
//! `crypthix-crypto` or `crypthix-core` (FS-01, FS-55, FS-94).
//!
//! In `crypthix-crypto`, `test-rng` is the seeded stream of the vector generator and `vectors`
//! exposes the inner CX-AEAD errors and raw entry points. In `crypthix-core`, `vectors` exposes
//! the keys, AADs and chunk constructors that bypass `ObjectSealer`'s binding to its object.
//! Only the `tests/` workspace and each crate's own tests use them. A release build could still
//! pick one up:
//!
//! - through a normal or build dependency that names it, under any name the dependency is
//!   renamed to;
//! - through a package feature that forwards to it, or to another feature of the same crate
//!   that enables it;
//! - through the crate's own default features.
//!
//! The first two are read from `cargo metadata`. Then `cargo tree`, without dev-dependencies,
//! resolves the whole workspace with default features, and every package that depends on a
//! guarded crate with `--all-features` on every target, and must show none of its guarded
//! features. Any failure to run or read `cargo tree` fails the check.
//!
//! Compiler flags can do the same behind Cargo's back: `--cfg feature="vectors"` turns a feature
//! on, `--cfg feature="pkg-config"` turns on a `zstd-sys` feature that cargo-deny's allow list
//! never sees, and `--cfg getrandom_backend=...` replaces the kernel source of every key and
//! nonce (FS-01). The check rejects any `--cfg feature=` and any `getrandom_backend` in every
//! variable Cargo reads compiler flags from (`RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
//! `CARGO_BUILD_RUSTFLAGS`, `CARGO_HOST_RUSTFLAGS` and each `CARGO_TARGET_<TRIPLE>_RUSTFLAGS`)
//! and anywhere in the repository's Cargo config files, which covers their `rustflags` under
//! `[build]`, `[host]` and `[target.<triple or cfg>]`.
//!
//! It also rejects the ways to link a system or a different libzstd instead of the bundled,
//! pinned one (FS-53) that cargo-deny cannot see:
//!
//! - `ZSTD_SYS_USE_PKG_CONFIG` in those files or in the environment;
//! - a `links` override for `zstd` (a `[target.<triple>.zstd]` table, or a `zstd` key under
//!   `[target.<triple>]`) in those files, which makes Cargo skip `zstd-sys`'s build script and
//!   link whatever the override names;
//! - a `[patch.<registry>]` or `[replace]` entry for `zstd`, `zstd-sys` or `zstd-safe`, under its
//!   own name or through `package = "..."`, in those files or in either workspace manifest,
//!   which swaps in another copy of the crate and its build script;
//! - a `paths` override in those files: it replaces any crate whose name matches a package in
//!   the listed directories, and the check does not read them to find out which, so every one
//!   is rejected.
//!
//! `cargo xtask check-zstd-link` then checks what the build actually linked.
//!
//! These checks cover only the repository's own build environment: the process environment of
//! the check and the Cargo config files inside the repository. A user-level
//! `~/.cargo/config.toml`, one in `$CARGO_HOME` or in a directory above the repository, and
//! `--config` on the command line are out of their reach. The backstop is the runtime check in
//! `crypthix-core`: `Compressor::new`, and `Decompressor::decode` before its first call into
//! libzstd, fail with `CompressError::Version` when the linked libzstd is not the version FS-53
//! pins.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs;
use std::process::Command;

use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, Package, PackageId};
use toml::{Table, Value};

use crate::process::{cargo, repo_root};

/// The guarded crates, each with its features that a release build must never enable.
const GUARDED: [(&str, &[&str]); 2] = [
    ("crypthix-crypto", &["test-rng", "vectors"]),
    ("crypthix-core", &["vectors"]),
];

/// Runs the check on the main workspace.
pub(crate) fn check() -> Result<(), String> {
    let metadata = MetadataCommand::new()
        .exec()
        .map_err(|error| format!("cargo metadata failed: {error}"))?;
    let mut problems = Vec::new();
    for (krate, test_only) in GUARDED {
        problems.extend(crate_problems(&metadata, krate, test_only)?);
    }
    let files = config_files();
    problems.extend(
        env_sources()
            .iter()
            .chain(&files)
            .flat_map(|(source, text)| flag_problems(source, text)),
    );
    problems.extend(
        files
            .iter()
            .flat_map(|(source, text)| links_problems(source, text)),
    );
    problems.extend(
        files
            .iter()
            .chain(&manifest_files())
            .flat_map(|(source, text)| override_problems(source, text)),
    );

    if problems.is_empty() {
        let names: Vec<String> = GUARDED
            .iter()
            .flat_map(|(krate, test_only)| {
                test_only
                    .iter()
                    .map(move |feature| format!("{krate}/{feature}"))
            })
            .collect();
        println!("features: no release build enables {}", names.join(", "));
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("feature rule violation: {problem}");
        }
        Err(format!(
            "{} release builds must not enable test-only features (FS-01)",
            problems.len()
        ))
    }
}

/// The problems with one guarded crate: manifests that enable or forward to its test-only
/// features, and release builds that resolve them.
fn crate_problems(
    metadata: &Metadata,
    krate: &str,
    test_only: &[&str],
) -> Result<Vec<String>, String> {
    let package = metadata
        .workspace_packages()
        .into_iter()
        .find(|package| package.name.as_str() == krate)
        .ok_or_else(|| format!("{krate} is not a workspace member"))?;
    let guarded = guarded_features(&package.features, test_only);

    let mut problems = Vec::new();
    for package in metadata.workspace_packages() {
        problems.extend(manifest_problems(package, krate, &guarded));
    }
    problems.extend(resolved_problems(krate, &["--workspace"], &guarded)?);
    for dependent in dependents(metadata, &package.id) {
        let args = ["--package", dependent, "--all-features", "--target", "all"];
        problems.extend(resolved_problems(krate, &args, &guarded)?);
    }
    Ok(problems)
}

/// The test-only features and every feature of the crate that turns one of them on, directly or
/// through other features.
fn guarded_features(
    features: &std::collections::BTreeMap<String, Vec<String>>,
    test_only: &[&str],
) -> BTreeSet<String> {
    let mut guarded: BTreeSet<String> = test_only
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

/// Problems in one package's manifest: dependencies on `krate` that turn on a guarded feature
/// outside dev-dependencies, and package features that forward to one.
fn manifest_problems(package: &Package, krate: &str, guarded: &BTreeSet<String>) -> Vec<String> {
    let mut problems = Vec::new();
    // The names this package refers to the crate by: its own name, or a rename.
    let mut aliases = BTreeSet::new();
    for dependency in &package.dependencies {
        if dependency.name != krate {
            continue;
        }
        let alias = dependency
            .rename
            .clone()
            .unwrap_or_else(|| krate.to_owned());
        problems.extend(dependency_problem(
            &package.name,
            krate,
            &alias,
            dependency.kind,
            &dependency.features,
            guarded,
        ));
        aliases.insert(alias);
    }
    if package.name.as_str() == krate {
        aliases.insert(krate.to_owned());
    }
    for (feature, enables) in &package.features {
        problems.extend(forwarding_problems(
            &package.name,
            krate,
            feature,
            enables,
            &aliases,
            guarded,
        ));
    }
    problems
}

/// A normal or build dependency on `krate` that turns on a guarded feature. Dev-dependencies
/// are fine: they never reach a release build.
fn dependency_problem(
    package: &str,
    krate: &str,
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
            "{package} depends on {krate} (as `{alias}`) with {} outside dev-dependencies",
            enabled.join(", ")
        )
    })
}

/// Package features that enable a guarded feature of `krate`:
/// `debug = ["crypthix-crypto/test-rng"]`, the same through a renamed dependency or `?/`, or, in
/// the crate itself, a default feature.
fn forwarding_problems(
    package: &str,
    krate: &str,
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
            let defaulted = (package == krate && feature == "default" && guarded.contains(value))
                .then_some(value.as_str());
            forwarded
                .or(defaulted)
                .map(|name| format!("{package} feature `{feature}` enables {krate}/{name}"))
        })
        .collect()
}

/// The workspace packages other than the crate that reach it through normal or build
/// dependencies, so `--all-features` on them could reach its features.
fn dependents<'a>(metadata: &'a Metadata, krate: &PackageId) -> Vec<&'a str> {
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
        .filter(|package| package.id != *krate && reaches(&edges, &package.id, krate))
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

/// Asks `cargo tree`, without dev-dependencies, which features of `krate` a build with `args`
/// resolves.
fn resolved_problems(
    krate: &str,
    args: &[&str],
    guarded: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let output = Command::new(cargo())
        .args(["tree", "--locked", "--edges", "no-dev"])
        .args(args)
        .args([
            "--invert", krate, "--depth", "0", "--prefix", "none", "--format", "{p}|{f}",
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
    resolved_in(krate, &String::from_utf8_lossy(&output.stdout), guarded)
        .map_err(|message| format!("cargo tree {}: {message}", args.join(" ")))
}

/// The settings a build reads from the environment: the compiler flag variables and
/// `ZSTD_SYS_USE_PKG_CONFIG`, as `(source, text)`.
fn env_sources() -> Vec<(String, String)> {
    let from_env = env::vars_os().filter_map(|(name, value)| {
        let name = name.into_string().ok()?;
        // A value that is not UTF-8 is read lossily: it still reaches rustc.
        is_rustflags_variable(&name).then(|| (name, value.to_string_lossy().into_owned()))
    });
    // Any value turns pkg-config on, so the variable's presence is reported, under its own name.
    let zstd = env::var_os(ZSTD_PKG_CONFIG)
        .map(|_| ("environment".to_owned(), ZSTD_PKG_CONFIG.to_owned()));
    from_env.chain(zstd).collect()
}

/// Whether Cargo passes the variable's value to rustc as flags: `RUSTFLAGS`,
/// `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`, `CARGO_HOST_RUSTFLAGS`, or
/// `CARGO_TARGET_<TRIPLE>_RUSTFLAGS` for any triple. Cargo matches variable names exactly, so
/// lower-case spellings are not flags.
fn is_rustflags_variable(name: &str) -> bool {
    const FIXED: [&str; 4] = [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_HOST_RUSTFLAGS",
    ];
    FIXED.contains(&name)
        || name
            .strip_prefix("CARGO_TARGET_")
            .and_then(|rest| rest.strip_suffix("_RUSTFLAGS"))
            .is_some_and(|triple| !triple.is_empty())
}

/// Both workspace manifests, as `(path, text)`, for their `[patch]` and `[replace]` tables.
fn manifest_files() -> Vec<(String, String)> {
    let root = repo_root();
    ["Cargo.toml", "tests/Cargo.toml"]
        .iter()
        .filter_map(|file| {
            fs::read_to_string(root.join(file))
                .ok()
                .map(|text| ((*file).to_owned(), text))
        })
        .collect()
}

/// `[patch.<registry>]` and `[replace]` entries that swap in another `zstd`, `zstd-sys` or
/// `zstd-safe`, and any `paths` override (see the module docs). Invalid TOML is reported by
/// `links_problems` for config files and by Cargo for manifests, so it is skipped here.
fn override_problems(source: &str, text: &str) -> Vec<String> {
    let Ok(config) = text.parse::<Table>() else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    if let Some(Value::Table(registries)) = config.get("patch") {
        for (registry, entries) in registries {
            let Value::Table(entries) = entries else {
                continue;
            };
            for (name, entry) in entries {
                let package = match entry {
                    Value::Table(entry) => entry.get("package").and_then(Value::as_str),
                    _ => None,
                };
                if let Some(krate) = [name.as_str()]
                    .into_iter()
                    .chain(package)
                    .find(|krate| ZSTD_CRATES.contains(krate))
                {
                    problems.push(format!(
                        "{source} patches {krate} for {registry}, replacing the pinned zstd (FS-53)"
                    ));
                }
            }
        }
    }
    if let Some(Value::Table(replaced)) = config.get("replace") {
        for spec in replaced.keys() {
            // `name:version` or `registry#name@version`; the name is what matters.
            let name = spec.rsplit(['#', '/']).next().unwrap_or(spec);
            let name = name.split([':', '@']).next().unwrap_or(name);
            if ZSTD_CRATES.contains(&name) {
                problems.push(format!(
                    "{source} replaces {spec}, swapping out the pinned zstd (FS-53)"
                ));
            }
        }
    }
    if config.contains_key("paths") {
        problems.push(format!(
            "{source} sets `paths`, which can replace zstd-sys or any other crate with a local \
             copy; use `[patch]` for a crate that is not zstd instead"
        ));
    }
    problems
}

/// The Cargo config files of both workspaces, as `(path, text)`. Files outside the repository
/// are out of reach (see the module docs).
fn config_files() -> Vec<(String, String)> {
    let root = repo_root();
    let files = [
        ".cargo/config.toml",
        ".cargo/config",
        "tests/.cargo/config.toml",
        "tests/.cargo/config",
    ];
    files
        .iter()
        .filter_map(|file| {
            fs::read_to_string(root.join(file))
                .ok()
                .map(|text| ((*file).to_owned(), text))
        })
        .collect()
}

/// A `links` override for `zstd` in a Cargo config file: `[target.<triple>.zstd]`, which makes
/// Cargo skip `zstd-sys`'s build script (it declares `links = "zstd"`) and link what the
/// override names. A file that is not valid TOML is reported too, so it cannot hide one.
fn links_problems(source: &str, text: &str) -> Vec<String> {
    let config: Table = match text.parse() {
        Ok(config) => config,
        Err(error) => return vec![format!("{source} is not valid TOML: {error}")],
    };
    let Some(Value::Table(targets)) = config.get("target") else {
        return Vec::new();
    };
    targets
        .iter()
        .filter(|(_, settings)| {
            matches!(settings, Value::Table(settings) if settings.contains_key(ZSTD_LINKS))
        })
        .map(|(target, _)| {
            format!(
                "{source} overrides the `{ZSTD_LINKS}` library for {target}, linking a system \
                 zstd instead of the pinned one (FS-53)"
            )
        })
        .collect()
}

/// Flags that turn on a feature or replace the `getrandom` backend, and a system zstd.
fn flag_problems(source: &str, text: &str) -> Vec<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let mut problems = Vec::new();
    if compact.contains(ZSTD_PKG_CONFIG) {
        problems.push(format!(
            "{source} sets {ZSTD_PKG_CONFIG}, linking a system zstd instead of the pinned one (FS-53)"
        ));
    }
    if compact.contains("getrandom_backend") {
        problems.push(format!(
            "{source} sets getrandom_backend, replacing the kernel RNG (FS-01)"
        ));
    }
    // `-C target-feature=+aes` is a CPU feature, not a crate feature.
    if compact.replace("target-feature=", "").contains("feature=") {
        problems.push(format!(
            "{source} sets a `--cfg feature=` flag, bypassing Cargo features (a test-only \
             feature, or a zstd-sys one such as pkg-config that cargo-deny cannot see)"
        ));
    }
    problems
}

/// The variable that makes `zstd-sys` link a system libzstd through pkg-config.
const ZSTD_PKG_CONFIG: &str = "ZSTD_SYS_USE_PKG_CONFIG";

/// The `links` name of `zstd-sys`, which a `[target.<triple>.zstd]` table overrides.
const ZSTD_LINKS: &str = "zstd";

/// The crates between `crypthix-core` and libzstd, and the `zstd` crate cargo-deny bans, none of
/// which a `[patch]` or `[replace]` may swap out.
const ZSTD_CRATES: [&str; 3] = ["zstd", "zstd-sys", "zstd-safe"];

/// The guarded features of `krate` in `cargo tree` lines of the form
/// `<package> <version> (<path>)|<f,..>`.
///
/// # Errors
///
/// If no line names the crate, so a changed output format cannot pass silently.
fn resolved_in(krate: &str, tree: &str, guarded: &BTreeSet<String>) -> Result<Vec<String>, String> {
    let prefix = format!("{krate} v");
    let lines: Vec<(&str, &str)> = tree
        .lines()
        .filter_map(|line| line.split_once('|'))
        .filter(|(package, _)| package.starts_with(&prefix))
        .collect();
    if lines.is_empty() {
        return Err(format!("no line for {krate} in its output"));
    }
    Ok(lines
        .iter()
        .flat_map(|(_, features)| features.split(','))
        .filter(|feature| guarded.contains(*feature))
        .map(|feature| format!("a release build resolves {krate}/{feature}"))
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

    /// The crypto crate, the first guarded one.
    const CRATE: &str = GUARDED[0].0;

    fn guarded() -> BTreeSet<String> {
        set(GUARDED[0].1)
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
            guarded_features(&features, GUARDED[0].1),
            set(&["bench", "deep", "test-rng", "vectors"])
        );
    }

    #[test]
    fn the_cores_vectors_feature_is_guarded() {
        let (krate, test_only) = GUARDED[1];
        assert_eq!(krate, "crypthix-core");
        let features = BTreeMap::from([("vectors".to_owned(), Vec::new())]);
        let guarded = guarded_features(&features, test_only);
        assert_eq!(guarded, set(&["vectors"]));
        let normal = dependency_problem(
            "crypthix-cli",
            krate,
            krate,
            DependencyKind::Normal,
            &strings(&["vectors"]),
            &guarded,
        );
        assert!(
            normal.is_some(),
            "a normal dependency enabled crypthix-core/vectors"
        );
        let forwarded = forwarding_problems(
            "crypthix-cli",
            krate,
            "debug",
            &strings(&["crypthix-core/vectors"]),
            &set(&[krate]),
            &guarded,
        );
        assert_eq!(forwarded.len(), 1, "{forwarded:?}");
        let leaked = "crypthix-core v0.0.0 (/x)|vectors\n";
        assert_eq!(
            resolved_in(krate, leaked, &guarded).map(|found| found.len()),
            Ok(1)
        );
        assert!(
            resolved_in(krate, "crypthix-crypto v0.0.0 (/x)|vectors\n", &guarded).is_err(),
            "another crate's line"
        );
    }

    #[test]
    fn normal_and_build_dependencies_may_not_enable_test_features() {
        let rng = strings(&["test-rng"]);
        let normal = dependency_problem(
            "crypthix-cli",
            CRATE,
            CRATE,
            DependencyKind::Normal,
            &rng,
            &guarded(),
        );
        assert!(normal.is_some(), "a normal dependency enabled test-rng");
        let build = dependency_problem(
            "crypthix-cli",
            CRATE,
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
            CRATE,
            DependencyKind::Development,
            &rng,
            &guarded(),
        );
        assert_eq!(dev, None);
        let none = dependency_problem(
            "crypthix-keys",
            CRATE,
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
        let problems = forwarding_problems(
            "crypthix-cli",
            CRATE,
            "debug",
            &enables,
            &aliases,
            &guarded(),
        );
        assert_eq!(problems.len(), 2, "{problems:?}");
        let unrelated = forwarding_problems(
            "crypthix-cli",
            CRATE,
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
        let defaults = forwarding_problems(
            CRATE,
            CRATE,
            "default",
            &strings(&["test-rng"]),
            &own,
            &guarded(),
        );
        assert_eq!(defaults.len(), 1);
        let fine = forwarding_problems(
            CRATE,
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
        assert_eq!(resolved_in(CRATE, clean, &guarded()), Ok(Vec::new()));
        let leaked = "crypthix-crypto v0.0.0 (/x)|test-rng,vectors\n";
        assert_eq!(
            resolved_in(CRATE, leaked, &guarded()).map(|found| found.len()),
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
    fn a_system_zstd_through_pkg_config_is_rejected() {
        let config = "[env]\nZSTD_SYS_USE_PKG_CONFIG = \"1\"\n";
        let problems = flag_problems(".cargo/config.toml", config);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(
            flag_problems("environment", ZSTD_PKG_CONFIG).len(),
            1,
            "the set variable is reported"
        );
    }

    #[test]
    fn every_rustflags_variable_is_read() {
        for name in [
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_HOST_RUSTFLAGS",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
        ] {
            assert!(is_rustflags_variable(name), "{name}");
        }
        for name in [
            "RUSTDOCFLAGS",
            "CARGO_TARGET_DIR",
            "CARGO_TARGET__RUSTFLAGS",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
            "cargo_build_rustflags",
        ] {
            assert!(!is_rustflags_variable(name), "{name}");
        }
    }

    #[test]
    fn zstd_feature_cfgs_in_flags_are_rejected() {
        let target = flag_problems(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
            "--cfg feature=\"pkg-config\"",
        );
        assert_eq!(target.len(), 1, "{target:?}");
        // CARGO_ENCODED_RUSTFLAGS separates flags with 0x1f, not spaces.
        let encoded = flag_problems(
            "CARGO_ENCODED_RUSTFLAGS",
            "--cfg\u{1f}feature=\"non-cargo\"",
        );
        assert_eq!(encoded.len(), 1, "{encoded:?}");
        let config = "[target.'cfg(unix)']\nrustflags = [\"--cfg\", \"feature = \\\"cmake\\\"\"]\n\
                      [host]\nrustflags = [\"-C\", \"opt-level=2\"]\n";
        assert_eq!(flag_problems(".cargo/config.toml", config).len(), 1);
        assert_eq!(
            flag_problems("CARGO_BUILD_RUSTFLAGS", "-C target-cpu=native"),
            Vec::<String>::new()
        );
        assert_eq!(
            flag_problems("RUSTFLAGS", "-C target-feature=+aes,+sse4.1"),
            Vec::<String>::new()
        );
        assert_eq!(
            flag_problems(
                "RUSTFLAGS",
                "-C target-feature=+aes --cfg feature=\"cmake\""
            )
            .len(),
            1
        );
    }

    #[test]
    fn patches_and_replacements_of_zstd_crates_are_rejected() {
        for config in [
            "[patch.crates-io]\nzstd-sys = { path = \"../zstd-sys\" }\n",
            "[patch.crates-io.zstd-safe]\ngit = \"https://example.com/zstd-rs\"\n",
            "[patch.'https://github.com/x/y']\nmine = { path = \"z\", package = \"zstd\" }\n",
            "[replace]\n\"zstd-sys:2.1.2+zstd.1.5.7\" = { path = \"z\" }\n",
            "[replace]\n\"registry+https://x#zstd-safe@8.2.0\" = { path = \"z\" }\n",
            "paths = [\"../vendor/zstd-sys\"]\n",
        ] {
            assert_eq!(override_problems("config", config).len(), 1, "{config}");
        }
        let fine = "[patch.crates-io]\nserde = { path = \"../serde\" }\n\
                    zstd-sys-like = { path = \"x\" }\n\
                    [replace]\n\"zstdx:1.0.0\" = { path = \"z\" }\n\
                    [alias]\npaths = \"run\"\n";
        assert_eq!(override_problems("config", fine), Vec::<String>::new());
        assert_eq!(override_problems("config", "[patch"), Vec::<String>::new());
    }

    #[test]
    fn the_repository_has_no_zstd_override() {
        let problems: Vec<String> = config_files()
            .iter()
            .chain(&manifest_files())
            .flat_map(|(source, text)| override_problems(source, text))
            .collect();
        assert_eq!(problems, Vec::<String>::new());
        assert_eq!(manifest_files().len(), 2, "both manifests are read");
    }

    #[test]
    fn a_links_override_for_zstd_is_rejected() {
        let table = "[target.x86_64-unknown-linux-gnu.zstd]\nrustc-link-lib = [\"zstd\"]\n";
        assert_eq!(links_problems("config", table).len(), 1, "a table");
        let dotted = "[target.aarch64-apple-darwin]\nzstd.rustc-link-search = [\"/opt\"]\n";
        assert_eq!(links_problems("config", dotted).len(), 1, "a dotted key");
        let inline = "target.x86_64-pc-windows-msvc.zstd = { rustc-link-lib = [\"zstd\"] }\n";
        assert_eq!(links_problems("config", inline).len(), 1, "an inline table");
        let fine = "[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\n\
                    [target.x86_64-unknown-linux-gnu.lzma]\nrustc-link-lib = [\"lzma\"]\n\
                    [alias]\nzstd = \"run\"\n";
        assert_eq!(links_problems("config", fine), Vec::<String>::new());
        assert_eq!(
            links_problems("config", "[target").len(),
            1,
            "invalid TOML is reported"
        );
    }

    #[test]
    fn output_without_the_crate_fails() {
        assert!(
            resolved_in(CRATE, "", &guarded()).is_err(),
            "empty output passed"
        );
        assert!(
            resolved_in(CRATE, "other v1.0.0|vectors\n", &guarded()).is_err(),
            "another crate passed"
        );
    }
}
