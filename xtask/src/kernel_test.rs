//! `cargo xtask kernel-test --kernel <image> [--expect <model>]`: the `crypthix-crypto` tests
//! inside another Linux kernel, booted with virtme-ng.
//!
//! Protected key memory (O1) depends on how the kernel accounts `memfd_secret` pages, which
//! changed with the CVE-2026-93243 fix: per process when mapped before it, per user when faulted
//! in after it. This boots a given kernel image, so the tests run on kernels of both kinds, not
//! only on the host's. It builds the tests on the host into a nextest archive, then boots the
//! image with `vng` (virtme-ng) under QEMU with KVM. The guest sees the host's file system as a
//! copy-on-write snapshot, so it runs the archive and the host's `cargo-nextest` in place. In it
//! the tests run as the invoking user, not root, whose `CAP_IPC_LOCK` kernels before the fix
//! exempt from the lock limit, with `CRYPTHIX_REQUIRE_SECRETMEM=1`: first the accounting probe
//! (`secret_memory_accounting_model`), which prints the model and, with `--expect`, fails unless
//! it is that one, then the whole suite. Any failure, or a guest that never finishes, fails the
//! command.
//!
//! The image is a file, typically `boot/vmlinuz-<version>` of a kernel package unpacked with
//! `dpkg-deb -x`; `vng` loads its modules from `lib/modules/<version>` under the directory that
//! holds `boot/`, so unpack the modules package into the same directory. Nothing is downloaded:
//! `vng --run` fetches a kernel itself only when given a version such as `v7.3`, and this passes
//! it an absolute path. Getting the image, and checking it, is the caller's job (see
//! `.github/workflows/kernel-test.yml` and docs/CONTRIBUTING.md).

use std::env;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::process::{cargo, repo_root, require_tool, run_status};

/// The secret-memory accounting models the probe test reports, by the names it prints.
const MODELS: [&str; 3] = ["per-process", "per-user", "unavailable"];

/// How to install the tools this needs (QEMU's on Debian and Ubuntu: [`qemu_install`]).
const VNG_INSTALL: &str = "pipx install virtme-ng==1.42";
const NEXTEST_INSTALL: &str = "cargo install cargo-nextest --locked";

/// Memory for the guest: the default 1 GiB is tight for test binaries running side by side.
const GUEST_MEMORY: &str = "4G";

/// The parsed arguments.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    /// The kernel image to boot.
    kernel: PathBuf,
    /// The accounting model the probe must report.
    expect: Option<String>,
}

/// What the arguments ask for.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Help,
    Run(Options),
}

/// Parses the arguments and runs the tests in the kernel they name.
pub(crate) fn run(args: &[String]) -> Result<(), String> {
    match parse(args)? {
        Request::Help => {
            println!("{}", usage());
            Ok(())
        }
        Request::Run(options) => run_in_kernel(&options),
    }
}

fn usage() -> String {
    format!(
        "usage: cargo xtask kernel-test --kernel <vmlinuz> [--expect <{}>]",
        MODELS.join(" | ")
    )
}

fn parse(args: &[String]) -> Result<Request, String> {
    let mut kernel = None;
    let mut expect = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(Request::Help),
            "--kernel" if kernel.is_none() => {
                kernel = Some(PathBuf::from(rest.next().ok_or_else(usage)?));
            }
            "--expect" if expect.is_none() => {
                let model = rest.next().ok_or_else(usage)?;
                if !MODELS.contains(&model.as_str()) {
                    return Err(usage());
                }
                expect = Some(model.clone());
            }
            _ => return Err(usage()),
        }
    }
    let kernel = kernel.ok_or_else(usage)?;
    Ok(Request::Run(Options { kernel, expect }))
}

fn run_in_kernel(options: &Options) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(
            "kernel-test boots Linux kernels with KVM, so it runs on Linux only".to_owned(),
        );
    }
    let kernel = kernel_image(&options.kernel)?;
    check_modules(&kernel)?;
    require_tool(&mut Command::new("vng"), "virtme-ng (vng)", VNG_INSTALL)?;
    let qemu = format!("qemu-system-{}", env::consts::ARCH);
    require_tool(&mut Command::new(&qemu), &qemu, &qemu_install())?;
    require_kvm()?;
    require_tool(
        Command::new(cargo()).arg("nextest"),
        "cargo-nextest",
        NEXTEST_INSTALL,
    )?;
    let nextest = find_on_path("cargo-nextest").ok_or_else(|| {
        format!("cargo-nextest is not on PATH, where the guest looks for it: {NEXTEST_INSTALL}")
    })?;
    let user = user_name()?;

    let root = repo_root();
    let archive = root
        .join("target")
        .join("kernel-test")
        .join("crypthix-crypto.tar.zst");
    println!("kernel-test: building the crypthix-crypto tests");
    run_status(
        Command::new(cargo())
            .current_dir(&root)
            .args([
                "nextest",
                "archive",
                "--package",
                "crypthix-crypto",
                "--all-features",
                "--locked",
                "--archive-file",
            ])
            .arg(&archive),
        "building the test archive failed (see above)",
    )?;
    let script = guest_script(&nextest, &archive, &root, options.expect.as_deref());
    println!("kernel-test: booting {}", kernel.display());
    run_status(
        Command::new("vng")
            .current_dir(&root)
            .arg("--run")
            .arg(&kernel)
            .args(["--user", &user, "--memory", GUEST_MEMORY, "--exec", &script]),
        "the tests failed in the guest kernel (see above)",
    )?;
    println!("kernel-test: passed in {}", kernel.display());
    Ok(())
}

/// How to install QEMU for this machine, and the static busybox `vng` puts in the guest's
/// initramfs, on Debian and Ubuntu.
fn qemu_install() -> String {
    let package = match env::consts::ARCH {
        "x86_64" => "qemu-system-x86",
        "aarch64" => "qemu-system-arm",
        _ => "qemu-system",
    };
    format!("sudo apt install {package} busybox-static")
}

/// The absolute path of the kernel image, which must be a file.
fn kernel_image(path: &Path) -> Result<PathBuf, String> {
    let kernel = path
        .canonicalize()
        .map_err(|error| format!("kernel image {}: {error}", path.display()))?;
    if kernel.is_file() {
        Ok(kernel)
    } else {
        Err(format!("kernel image {} is not a file", kernel.display()))
    }
}

/// Fails if an image in a `boot/` directory, as a kernel package unpacks it, has no modules
/// beside it, where `vng` looks: without them a distribution kernel cannot mount the host's
/// file system and the guest fails to boot with a less helpful error.
fn check_modules(kernel: &Path) -> Result<(), String> {
    let Some(boot) = kernel.parent().filter(|dir| dir.ends_with("boot")) else {
        return Ok(());
    };
    let root = boot.parent().unwrap_or(boot);
    if root.join("lib/modules").is_dir() || root.join("usr/lib/modules").is_dir() {
        Ok(())
    } else {
        Err(format!(
            "no lib/modules in {}: unpack the kernel's modules package there too \
             (dpkg-deb -x linux-modules-<version>.deb {})",
            root.display(),
            root.display()
        ))
    }
}

/// Fails unless this user may open `/dev/kvm`: without KVM, QEMU emulates the CPU and the
/// tests take many times longer.
fn require_kvm() -> Result<(), String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map(drop)
        .map_err(|error| {
            format!(
                "cannot open /dev/kvm ({error}): enable virtualisation in the firmware, then \
                 sudo usermod -aG kvm \"$USER\" and log in again"
            )
        })
}

/// The name of the user running this, whom the guest runs the tests as.
fn user_name() -> Result<String, String> {
    let output = Command::new("id")
        .arg("-un")
        .output()
        .map_err(|error| format!("cannot run id: {error}"))?;
    let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if output.status.success() && !name.is_empty() {
        Ok(name)
    } else {
        Err("`id -un` names no user to run the tests as in the guest".to_owned())
    }
}

/// The first `name` in a `PATH` directory.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The shell command the guest runs: the probe on its own, then the whole suite.
fn guest_script(nextest: &Path, archive: &Path, root: &Path, expect: Option<&str>) -> String {
    let run = format!(
        "{} nextest run --archive-file {} --workspace-remap {} --profile ci",
        quote(&nextest.to_string_lossy()),
        quote(&archive.to_string_lossy()),
        quote(&root.to_string_lossy()),
    );
    let expect = expect.map_or_else(String::new, |model| {
        format!(" CRYPTHIX_EXPECT_SECRETMEM_ACCOUNTING={}", quote(model))
    });
    let probe = quote(
        "binary_id(crypthix-crypto::secure_mem_linux) & test(=secret_memory_accounting_model)",
    );
    format!(
        "set -e; export CRYPTHIX_REQUIRE_SECRETMEM=1{expect}; \
         echo \"kernel-test: guest kernel $(uname -r), RLIMIT_MEMLOCK $(ulimit -l) KiB, \
         user $(id -un)\"; \
         {run} --run-ignored only --no-capture -E {probe}; \
         {run}"
    )
}

/// `text` as one word for a POSIX shell.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn a_kernel_and_an_expected_model_are_parsed() {
        assert_eq!(
            parse(&args(&["--kernel", "boot/vmlinuz", "--expect", "per-user"])),
            Ok(Request::Run(Options {
                kernel: PathBuf::from("boot/vmlinuz"),
                expect: Some("per-user".to_owned()),
            }))
        );
        assert_eq!(
            parse(&args(&["--expect", "per-process", "--kernel", "k"])),
            Ok(Request::Run(Options {
                kernel: PathBuf::from("k"),
                expect: Some("per-process".to_owned()),
            })),
            "in either order"
        );
        assert_eq!(
            parse(&args(&["--kernel", "k"])),
            Ok(Request::Run(Options {
                kernel: PathBuf::from("k"),
                expect: None,
            }))
        );
    }

    #[test]
    fn help_wins_over_everything_else() {
        assert_eq!(parse(&args(&["--help"])), Ok(Request::Help));
        assert_eq!(parse(&args(&["--kernel", "k", "-h"])), Ok(Request::Help));
    }

    #[test]
    fn bad_arguments_are_usage_errors() {
        for bad in [
            &[][..],
            &["--kernel"],
            &["--expect", "per-user"],
            &["--kernel", "k", "--expect"],
            &["--kernel", "k", "--expect", "per-thread"],
            &["--kernel", "a", "--kernel", "b"],
            &[
                "--kernel", "k", "--expect", "per-user", "--expect", "per-user",
            ],
            &["--kernel", "k", "v7.3"],
            &["--memory", "8G"],
        ] {
            let error = parse(&args(bad)).expect_err(&format!("{bad:?} accepted"));
            assert!(error.starts_with("usage:"), "{error}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_kernel_image_fails_before_any_tool_is_needed() {
        let error = run(&args(&["--kernel", "/nonexistent/vmlinuz"])).expect_err("no image");
        assert!(error.contains("/nonexistent/vmlinuz"), "{error}");
    }

    #[test]
    fn a_directory_is_not_a_kernel_image() {
        let error = kernel_image(&repo_root()).expect_err("a directory");
        assert!(error.ends_with("is not a file"), "{error}");
    }

    #[test]
    fn modules_are_required_beside_a_packaged_image_only() {
        let root = repo_root();
        assert_eq!(check_modules(&root.join("xtask/Cargo.toml")), Ok(()));
        let error = check_modules(&root.join("boot/vmlinuz")).expect_err("no lib/modules here");
        assert!(error.contains("dpkg-deb -x"), "{error}");
    }

    #[test]
    fn words_are_quoted_for_the_shell() {
        assert_eq!(quote("plain"), "'plain'");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("$(x)"), "'$(x)'");
    }

    #[test]
    fn the_guest_runs_the_probe_then_the_suite_and_stops_at_a_failure() {
        let script = guest_script(
            Path::new("/bin/cargo-nextest"),
            Path::new("/r/t/a.tar.zst"),
            Path::new("/r"),
            Some("per-user"),
        );
        assert!(script.starts_with("set -e; "), "{script}");
        assert!(
            script.contains(
                "export CRYPTHIX_REQUIRE_SECRETMEM=1 CRYPTHIX_EXPECT_SECRETMEM_ACCOUNTING='per-user';"
            ),
            "{script}"
        );
        let run = "'/bin/cargo-nextest' nextest run --archive-file '/r/t/a.tar.zst' \
                   --workspace-remap '/r' --profile ci";
        let probe = script
            .find(&format!("{run} --run-ignored only"))
            .expect("the probe");
        assert!(
            script.ends_with(&format!("; {run}")),
            "the suite comes last: {script}"
        );
        assert!(probe < script.len() - run.len(), "{script}");
        let without = guest_script(Path::new("/n"), Path::new("/a"), Path::new("/r"), None);
        assert!(
            !without.contains("CRYPTHIX_EXPECT_SECRETMEM_ACCOUNTING"),
            "{without}"
        );
    }
}
