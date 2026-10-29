//! `cargo xtask ci [<job> ...] [--base <rev>]`: the CI jobs, runnable locally.
//!
//! Each job in `.github/workflows/ci.yml` runs one of these, so a local run checks exactly
//! what CI checks. With no job named, every job runs in turn. `--base` is the commit the
//! changes start from (default `origin/master`); the `pr` job checks the commit messages, file
//! hygiene and secrets of the commits after it. CI runs `pr` on pull requests only: a push to
//! master brings no commits a pull request has not already checked.

use std::env;
use std::process::Command;

use crate::process::{cargo, repo_root, require_tool, run_status};
use crate::{commits, docs_check, pre_commit, side, vendored};

/// One CI job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Job {
    /// Formatting, layer rules, docs, vendored vectors, typos and workflow lint.
    Lint,
    /// Commit messages, file hygiene and secrets of the commits after `--base`.
    Pr,
    /// Clippy on both workspaces.
    Clippy,
    /// The main workspace tests and doctests.
    Test,
    /// Rustdoc with warnings as errors.
    Doc,
    /// cargo-deny on both workspaces and unused dependencies.
    Deny,
    /// The `tests/` workspace tests and the vector check.
    Side,
}

const JOBS: [Job; 7] = [
    Job::Lint,
    Job::Pr,
    Job::Clippy,
    Job::Test,
    Job::Doc,
    Job::Deny,
    Job::Side,
];

impl Job {
    const fn name(self) -> &'static str {
        match self {
            Job::Lint => "lint",
            Job::Pr => "pr",
            Job::Clippy => "clippy",
            Job::Test => "test",
            Job::Doc => "doc",
            Job::Deny => "deny",
            Job::Side => "side",
        }
    }
}

/// The base used when `--base` is not given.
const DEFAULT_BASE: &str = "origin/master";

/// A base that names no commit: GitHub sends all zeros for the first push of a branch.
const NULL_COMMIT: &str = "0000000000000000000000000000000000000000";

/// Parses the arguments and runs the jobs.
pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let mut jobs = Vec::new();
    let mut base = DEFAULT_BASE.to_owned();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--base" {
            base.clone_from(rest.next().ok_or_else(usage)?);
        } else if let Some(job) = JOBS.iter().find(|job| job.name() == arg) {
            jobs.push(*job);
        } else {
            return Err(usage());
        }
    }
    if base.is_empty() || base == NULL_COMMIT {
        DEFAULT_BASE.clone_into(&mut base);
    }
    if jobs.is_empty() {
        jobs = JOBS.to_vec();
    }
    // The jobs name paths relative to the repository root.
    env::set_current_dir(repo_root())
        .map_err(|error| format!("cannot enter the repository root: {error}"))?;
    for job in jobs {
        println!("ci: {}", job.name());
        match job {
            Job::Lint => lint()?,
            Job::Pr => pr(&base)?,
            Job::Clippy => clippy()?,
            Job::Test => test()?,
            Job::Doc => doc()?,
            Job::Deny => deny()?,
            Job::Side => side()?,
        }
    }
    println!("ci: all jobs passed");
    Ok(())
}

fn usage() -> String {
    let names: Vec<&str> = JOBS.iter().map(|job| job.name()).collect();
    format!(
        "usage: cargo xtask ci [{}] [--base <rev>]",
        names.join(" | ")
    )
}

fn step(name: &str) {
    println!("ci: - {name}");
}

fn lint() -> Result<(), String> {
    step("formatting");
    run_status(
        Command::new(cargo()).args(["fmt", "--all", "--check"]),
        "run `cargo fmt --all`",
    )?;
    run_status(
        Command::new(cargo()).args([
            "fmt",
            "--manifest-path",
            "tests/Cargo.toml",
            "--all",
            "--check",
        ]),
        "run `cargo fmt --manifest-path tests/Cargo.toml --all`",
    )?;
    step("layer rules");
    crate::check_layers()?;
    step("docs");
    docs_check::check()?;
    step("vendored vectors");
    vendored::check()?;
    step("typos");
    require_tool(
        &mut Command::new("typos"),
        "typos",
        "cargo install typos-cli --locked",
    )?;
    run_status(
        &mut Command::new("typos"),
        "typos found misspellings (see above)",
    )?;
    step("workflows");
    require_tool(
        &mut Command::new("actionlint"),
        "actionlint",
        "go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12",
    )?;
    run_status(
        &mut Command::new("actionlint"),
        "actionlint found problems in .github/workflows (see above)",
    )?;
    require_tool(
        &mut Command::new("zizmor"),
        "zizmor",
        "cargo install zizmor --locked",
    )?;
    run_status(
        Command::new("zizmor").args(["--offline", "--no-progress", ".github"]),
        "zizmor found problems in .github (see above)",
    )
}

fn pr(base: &str) -> Result<(), String> {
    step(&format!("commits after {base}"));
    commits::check(base)?;
    pre_commit::hygiene_and_secrets(&pre_commit::Changes::Since(base.to_owned()))
}

fn clippy() -> Result<(), String> {
    let lint_args = ["--all-targets", "--locked", "--", "-D", "warnings"];
    run_status(
        Command::new(cargo())
            .args(["clippy", "--workspace", "--all-features"])
            .args(lint_args),
        "clippy found problems (see above)",
    )?;
    // The cargo-fuzz crate is left out: libFuzzer needs a C++ compiler even to check, and its
    // binaries only call the harness. The fuzz job builds it.
    run_status(
        Command::new(cargo())
            .args([
                "clippy",
                "--manifest-path",
                "tests/Cargo.toml",
                "--package",
                "crypthix-fuzz-harness",
                "--package",
                "crypthix-vector-gen",
            ])
            .args(lint_args),
        "clippy found problems in tests/ (see above)",
    )
}

fn test() -> Result<(), String> {
    require_tool(
        Command::new(cargo()).arg("nextest"),
        "cargo-nextest",
        "cargo install cargo-nextest --locked",
    )?;
    run_status(
        Command::new(cargo()).args([
            "nextest",
            "run",
            "--workspace",
            "--all-features",
            "--locked",
        ]),
        "tests failed (see above)",
    )?;
    // nextest does not run doctests.
    run_status(
        Command::new(cargo()).args(["test", "--doc", "--workspace", "--all-features", "--locked"]),
        "doctests failed (see above)",
    )
}

fn doc() -> Result<(), String> {
    run_status(
        Command::new(cargo())
            .args([
                "doc",
                "--workspace",
                "--no-deps",
                "--all-features",
                "--locked",
            ])
            .env("RUSTDOCFLAGS", "-D warnings"),
        "rustdoc found problems (see above)",
    )
}

fn deny() -> Result<(), String> {
    require_tool(
        Command::new(cargo()).arg("deny"),
        "cargo-deny",
        "cargo install cargo-deny --locked",
    )?;
    run_status(
        Command::new(cargo()).args(["deny", "--locked", "check"]),
        "cargo deny found problems (see above)",
    )?;
    side::side_deny()?;
    require_tool(
        Command::new(cargo()).arg("shear"),
        "cargo-shear",
        "cargo install cargo-shear --locked",
    )?;
    run_status(
        Command::new(cargo()).arg("shear"),
        "cargo shear found unused dependencies (see above)",
    )?;
    run_status(
        Command::new(cargo()).arg("shear").current_dir("tests"),
        "cargo shear found unused dependencies in tests/ (see above)",
    )
}

fn side() -> Result<(), String> {
    side::side_tests()?;
    side::vectors_check()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_names_are_unique() {
        let mut names: Vec<&str> = JOBS.iter().map(|job| job.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), JOBS.len(), "two jobs share a name");
    }

    #[test]
    fn an_unknown_job_is_a_usage_error() {
        let error = run(&["nope".to_owned()]).expect_err("unknown job accepted");
        assert!(error.starts_with("usage:"), "{error}");
    }
}
