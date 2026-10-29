# Contributing to CryptHix

Thank you for your interest in CryptHix. The project is in its design phase, so please open an issue to discuss a change before sending a pull request.

## Contributor License Agreement

CryptHix is dual-licensed under the GNU AGPL-3.0 and a [commercial licence](COMMERCIAL.md). To keep offering both, every contributor must agree to a Contributor License Agreement (CLA) before their first pull request is merged. The CLA lets the project distribute your contribution under both licences; you keep the copyright to your work.

A CLA bot will ask you to sign when you open your first pull request. Pull requests cannot be merged until the CLA is signed.

## Before you open a pull request

Follow the [Rust style guide](style-guide.md). Enable the pre-commit hook once with `cargo xtask install-hooks` (it needs [gitleaks](https://github.com/gitleaks/gitleaks)), and run the CI checks locally before pushing:

```bash
cargo fmt --all
cargo xtask ci            # every job below; or name some: cargo xtask ci lint test
```

If you change a parser, also fuzz it for a few minutes on nightly, for example `cargo xtask fuzz cbor_differential --time 300` (see [Testing](style-guide.md#testing)).

## Commit messages

One line, `<type>[(<scope>)]: <summary>`, with no body and no trailers, for example `fix(cbor): reject non-shortest map heads`. The types are `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `ci`, `perf`, `build`, `style` and `revert`. CI checks every commit of a pull request (`cargo xtask check-commits <base>`); merge commits and bot commits are skipped.

## Continuous integration

Every job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs one `cargo xtask ci <job>`, so the local command checks the same things CI does. All jobs start at once; `CI OK` is the only required check.

| Job | Checks | Tools it needs locally |
| --- | --- | --- |
| `lint` | Formatting of both workspaces, layer rules, `check-docs`, `check-vendored`, typos, workflow lint, commit messages, and file hygiene and secrets on the commits after `--base` (default `origin/master`) | [typos](https://github.com/crate-ci/typos), [actionlint](https://github.com/rhysd/actionlint), [zizmor](https://docs.zizmor.sh), gitleaks |
| `clippy` | Clippy on both workspaces, warnings as errors | |
| `test` | Main workspace tests (nextest) and doctests | [cargo-nextest](https://nexte.st) |
| `doc` | Rustdoc, warnings as errors | |
| `deny` | cargo-deny on both lockfiles, unused dependencies | cargo-deny, [cargo-shear](https://github.com/Boshen/cargo-shear) |
| `side` | The `tests/` workspace tests and `vectors --check` | |

Pull requests also get a 20-second fuzz run of every target when a parser or the fuzz harness changes, and an advisory mutation test of the changed lines (cargo-mutants). Each tool's `cargo xtask` error names how to install it.

[`.github/workflows/scheduled.yml`](../.github/workflows/scheduled.yml) runs the long checks: every night 20 minutes of fuzzing per target, property tests at 4096 cases in release mode, Miri, fresh advisories, macOS, Windows and Linux arm64, and coverage; every week a full mutation run, external links, a full-history secret scan and a runner capability probe. A pull request that edits it runs it with short limits.

The workflows pin every action to a commit SHA, start from `permissions: {}`, never persist the checkout token, and only `master` writes the build cache. Changes to `.github/`, the deny and gitleaks configs, the toolchain, `xtask/` and the lockfiles need the maintainer's review ([`CODEOWNERS`](../.github/CODEOWNERS)).

## Reporting security issues

Do not open a public issue for a security vulnerability; follow the [security policy](SECURITY.md).
