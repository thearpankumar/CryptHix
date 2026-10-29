# Contributing to CryptHix

Thank you for your interest in CryptHix. The project is in its design phase, so please open an issue to discuss a change before sending a pull request.

## Contributor License Agreement

CryptHix is dual-licensed under the GNU AGPL-3.0 and a [commercial licence](COMMERCIAL.md). To keep offering both, every contributor must agree to a Contributor License Agreement (CLA) before their first pull request is merged. The CLA lets the project distribute your contribution under both licences; you keep the copyright to your work.

A CLA bot will ask you to sign when you open your first pull request. Pull requests cannot be merged until the CLA is signed.

## Before you open a pull request

Follow the [Rust style guide](style-guide.md). Enable the pre-commit hook once with `cargo xtask install-hooks` (it needs [gitleaks](https://github.com/gitleaks/gitleaks)), and run the local checks before pushing:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo xtask check-layers
cargo deny check
cargo xtask test-extra
```

If you change a parser, also fuzz it for a few minutes on nightly, for example `cargo xtask fuzz cbor_differential --time 300` (see [Testing](style-guide.md#testing)).

## Reporting security issues

Do not open a public issue for a security vulnerability. Email **arpankumar1119@gmail.com** instead.
