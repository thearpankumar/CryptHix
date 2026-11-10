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

If you change a parser, `crypthix-crypto` or the data path in `crypthix-core`, also fuzz it for a few minutes on nightly, for example `cargo xtask fuzz cbor_differential --time 300`, `cargo xtask fuzz cx_open --time 300` or `cargo xtask fuzz decompress --time 300` (see [Testing](style-guide.md#testing)).

## Commit messages

One line, `<type>[(<scope>)]: <summary>`, with no body and no trailers, for example `fix(cbor): reject non-shortest map heads`. The types are `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `ci`, `perf`, `build`, `style` and `revert`. CI checks every commit of a pull request (`cargo xtask check-commits <base>`); merge commits and bot commits are skipped.

## Continuous integration

Every job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs one `cargo xtask ci <job>`, so the local command checks the same things CI does. All jobs start at once; `CI OK` is the only required check.

| Job | Checks | Tools it needs locally |
| --- | --- | --- |
| `lint` | Formatting of both workspaces, layer rules, `check-docs`, `check-vendored`, typos and workflow lint | [typos](https://github.com/crate-ci/typos), [actionlint](https://github.com/rhysd/actionlint), [zizmor](https://docs.zizmor.sh) |
| `pr` (pull requests only) | Commit messages, file hygiene and secrets of the commits after `--base` (default `origin/master`) | gitleaks |
| `clippy` | Clippy on both workspaces, warnings as errors | |
| `test` | Main workspace tests (nextest) and doctests | [cargo-nextest](https://nexte.st) |
| `doc` | Rustdoc, warnings as errors | |
| `deny` | cargo-deny on both lockfiles, unused dependencies | cargo-deny, [cargo-shear](https://github.com/Boshen/cargo-shear) |
| `side` | The `tests/` workspace tests and `vectors --check` | |

Pull requests also get an external link check ([lychee](https://lychee.cli.rs), `lychee.toml`) of the Markdown files they change, a 20-second fuzz run of every target when a parser or the fuzz harness changes, and an advisory mutation test of the changed lines (cargo-mutants). These jobs and `pr` look at what a pull request changes, so they do not run on pushes to master, whose commits a pull request already checked. Each tool's `cargo xtask` error names how to install it. When `crypthix-crypto`, `crypthix-types` or `crypthix-core` changes, and on master, `windows-clippy` lints `crypthix-crypto` and `crypthix-core` for `x86_64-pc-windows-gnu`, cross-compiled on Linux, so the code `secure_mem` compiles on other systems, and the libzstd that `crypthix-core` builds from source, are checked before the nightly platform runs; locally that is `cargo clippy -p crypthix-crypto -p crypthix-core --all-features --all-targets --target x86_64-pc-windows-gnu -- -D warnings`, with the target added (`rustup target add x86_64-pc-windows-gnu`) and MinGW's `x86_64-w64-mingw32-gcc` installed.

### Kernel test

Protected key memory (`secure_mem`, O1) behaves differently on kernels with the CVE-2026-93243 fix, which charge `memfd_secret` pages to the user when they are faulted in, than on older ones, which check each mapping against its own process's `RLIMIT_MEMLOCK` when it is mapped. CI runners and most development machines run an older kernel, so the `kernel-test` job ([`.github/workflows/kernel-test.yml`](../.github/workflows/kernel-test.yml)) boots one kernel of each kind in QEMU with [virtme-ng](https://github.com/arighi/virtme-ng) and runs the `crypthix-crypto` tests inside it, with `CRYPTHIX_REQUIRE_SECRETMEM=1`. It runs on pull requests that change `crypthix-crypto`, `crypthix-types`, the lockfile, the toolchain, `.config/nextest.toml` or the job itself, on master and every night, and takes about five minutes per kernel. Both kernels are pinned Ubuntu mainline builds: [v7.3.3](https://kernel.ubuntu.com/mainline/v7.3.3/), which has the fix, and [v6.12.112](https://kernel.ubuntu.com/mainline/v6.12.112/), the last 6.12 release before its backport. The job checks each package against a SHA-256 pinned in the workflow and that hash against the build's published `CHECKSUMS` file, and the accounting probe in the guest must report the model the kernel is pinned for (`per-user` or `per-process`).

To run it locally you need Linux with KVM (your user in the `kvm` group), QEMU with a static busybox, virtme-ng and cargo-nextest. On Debian or Ubuntu, for x86-64:

```bash
sudo apt install qemu-system-x86 busybox-static pipx
pipx install virtme-ng==1.42
cargo install cargo-nextest --locked
```

Then download a kernel's `linux-image-unsigned-…_amd64.deb` and `linux-modules-…_amd64.deb` from its directory on [kernel.ubuntu.com/mainline](https://kernel.ubuntu.com/mainline/) (for example `v7.3.3/amd64/`), check them against the `CHECKSUMS` file there, unpack both into one directory, and boot its image:

```bash
grep -E '^[0-9a-f]{64}  ' CHECKSUMS | sha256sum --ignore-missing -c   # its SHA-256 lines
mkdir kernel
dpkg-deb -x linux-image-unsigned-*.deb kernel
dpkg-deb -x linux-modules-*.deb kernel
cargo xtask kernel-test --kernel kernel/boot/vmlinuz-* --expect per-user   # per-process for a kernel without the fix
```

`cargo xtask kernel-test` downloads nothing itself: it fails with the install command when `vng`, QEMU, `/dev/kvm` or cargo-nextest is missing. It builds the tests into a nextest archive on the host, boots the image with `vng`, runs the accounting probe (`secret_memory_accounting_model`, an ignored test in `tests/secure_mem_linux.rs`) and then the whole suite as your user, and fails if either fails.

[`.github/workflows/scheduled.yml`](../.github/workflows/scheduled.yml) runs the long checks: every night 20 minutes of fuzzing per target, property tests at 4096 cases in release mode, Miri, the `compile_fail` doctests on nightly (only nightly rustdoc checks their pinned error codes), fresh advisories, macOS, Windows and Linux arm64, the kernel test, and coverage; every week a full mutation run, external links, a full-history secret scan and a runner capability probe. A pull request that edits it runs it with short limits.

The workflows pin every action to a commit SHA, start from `permissions: {}`, never persist the checkout token, and only `master` writes the build cache. Changes to `.github/`, the deny and gitleaks configs, the toolchain, `xtask/` and the lockfiles need the maintainer's review ([`CODEOWNERS`](../.github/CODEOWNERS)).

## Reporting security issues

Do not open a public issue for a security vulnerability; follow the [security policy](SECURITY.md).
