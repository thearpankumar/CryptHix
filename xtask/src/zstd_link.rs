//! `cargo xtask check-zstd-link [--target <triple>]`: `zstd-sys` linked the libzstd it built
//! from its own vendored sources, statically (FS-53).
//!
//! `crypthix-core` checks at run time that libzstd reports version 1.5.7, but a system libzstd
//! 1.5.7 passes that too, built with whatever options its distribution chose. cargo-deny bans
//! the `zstd-sys` features that link a system library and `cargo xtask check-features` rejects
//! the settings that do it behind Cargo's back, but neither looks at what a build actually did.
//! This check does: it asks `cargo check` for `crypthix-core`'s build, takes `zstd-sys`'s
//! `build-script-executed` message, and reads both what Cargo reports it will pass to rustc and
//! the build script's own `output` file next to its `OUT_DIR`. Each must link only
//! `static=zstd` and search only inside that `OUT_DIR`, where the build script put the library
//! it compiled with `cc`. A system library through pkg-config adds a `/usr` (or `/opt`, Homebrew,
//! vcpkg) search path and a dynamic `zstd`; a `links` override skips the build script, so there
//! is no `output` file. Either fails.
//!
//! `cargo check` runs build scripts, and reuses the run of an earlier `cargo build` or `cargo
//! test` with the same profile, so after a test run the check costs a second.

use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::process::{Command, Stdio};

use cargo_metadata::Message;

use crate::process::cargo;

/// The library `zstd-sys`'s build script compiles with `cc` and links.
const LIBRARY: &str = "zstd";

/// What a `zstd-sys` build passes to rustc for linking.
#[derive(Debug, PartialEq, Eq)]
enum Directive {
    /// `rustc-link-lib=[KIND=]NAME`, kept whole after the `=`.
    Lib(String),
    /// `rustc-link-search=[KIND=]PATH`, kept whole after the `=`.
    Search(String),
    /// `rustc-link-arg*` and `rustc-flags`, which can name libraries and paths too.
    Other(String),
}

/// Runs the check for the host, or for `--target <triple>`.
pub(crate) fn check(args: &[String]) -> Result<(), String> {
    let target = match args {
        [] => None,
        [flag, triple] if flag == "--target" => Some(triple.as_str()),
        _ => return Err("usage: cargo xtask check-zstd-link [--target <triple>]".to_owned()),
    };
    let mut command = Command::new(cargo());
    command
        .args([
            "check",
            "--package",
            "crypthix-core",
            "--all-features",
            "--locked",
            "--message-format=json-render-diagnostics",
        ])
        .stdout(Stdio::piped());
    if let Some(target) = target {
        command.args(["--target", target]);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot run cargo check: {error}"))?;
    let stdout = child.stdout.take().ok_or("cargo check gave no output")?;
    let mut runs = Vec::new();
    for message in Message::parse_stream(BufReader::new(stdout)) {
        let message = message.map_err(|error| format!("cannot read cargo's output: {error}"))?;
        if let Message::BuildScriptExecuted(script) = message
            && script.package_id.repr.contains("#zstd-sys@")
        {
            runs.push(script);
        }
    }
    let status = child
        .wait()
        .map_err(|error| format!("cargo check did not finish: {error}"))?;
    if !status.success() {
        return Err("cargo check -p crypthix-core failed (see above)".to_owned());
    }
    if runs.is_empty() {
        return Err("the build ran no zstd-sys build script".to_owned());
    }

    let mut problems = Vec::new();
    for run in &runs {
        let out_dir = run.out_dir.as_std_path();
        let reported: Vec<Directive> = run
            .linked_libs
            .iter()
            .map(|lib| Directive::Lib(lib.to_string()))
            .chain(
                run.linked_paths
                    .iter()
                    .map(|path| Directive::Search(path.to_string())),
            )
            .collect();
        problems.extend(link_problems("cargo", &reported, out_dir));
        // The build script writes `output` beside its OUT_DIR; a links override runs none.
        let output = out_dir.with_file_name("output");
        match fs::read_to_string(&output) {
            Ok(text) => {
                let source = output.display().to_string();
                problems.extend(link_problems(&source, &directives(&text), out_dir));
            }
            Err(_) => problems.push(format!(
                "no build script output beside {}: zstd-sys's build script did not run, so a \
                 `links` override supplied the library",
                out_dir.display()
            )),
        }
    }
    if problems.is_empty() {
        println!(
            "zstd link: zstd-sys links its own libzstd statically ({} build script run{})",
            runs.len(),
            if runs.len() == 1 { "" } else { "s" }
        );
        Ok(())
    } else {
        for problem in &problems {
            eprintln!("zstd link: {problem}");
        }
        Err(format!(
            "zstd-sys does not link its vendored libzstd statically ({} problems, FS-53)",
            problems.len()
        ))
    }
}

/// The link directives in a build script's output: lines `cargo:KEY=VALUE` or `cargo::KEY=VALUE`.
/// Other lines (the `cc` crate's own logging) are ignored.
fn directives(output: &str) -> Vec<Directive> {
    output
        .lines()
        .filter_map(|line| {
            let rest = line
                .strip_prefix("cargo::")
                .or_else(|| line.strip_prefix("cargo:"))?;
            let (key, value) = rest.split_once('=')?;
            match key {
                "rustc-link-lib" => Some(Directive::Lib(value.to_owned())),
                "rustc-link-search" => Some(Directive::Search(value.to_owned())),
                "rustc-flags" => Some(Directive::Other(rest.to_owned())),
                _ if key.starts_with("rustc-link-arg") => Some(Directive::Other(rest.to_owned())),
                _ => None,
            }
        })
        .collect()
}

/// What is wrong with a set of link directives: a library other than `static=zstd`, no
/// `static=zstd` at all, a search path outside `out_dir` (or none inside it), or any linker
/// argument or flag.
fn link_problems(source: &str, directives: &[Directive], out_dir: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let mut static_zstd = false;
    let mut searches_out_dir = false;
    for directive in directives {
        match directive {
            Directive::Lib(lib) if *lib == format!("static={LIBRARY}") => static_zstd = true,
            Directive::Lib(lib) => {
                problems.push(format!("{source} links `{lib}`, not static={LIBRARY}"));
            }
            Directive::Search(search) => {
                // `KIND=PATH`, or a bare `PATH` (kind `all`).
                let path = match search.split_once('=') {
                    Some(("native" | "all" | "dependency" | "crate" | "framework", path)) => path,
                    _ => search.as_str(),
                };
                if Path::new(path).starts_with(out_dir) {
                    searches_out_dir = true;
                } else {
                    problems.push(format!(
                        "{source} searches {path} for libraries, outside zstd-sys's OUT_DIR {}",
                        out_dir.display()
                    ));
                }
            }
            Directive::Other(line) => {
                problems.push(format!("{source} passes the linker `{line}`"));
            }
        }
    }
    if !static_zstd {
        problems.push(format!("{source} does not link static={LIBRARY}"));
    }
    if !searches_out_dir {
        problems.push(format!(
            "{source} does not search zstd-sys's OUT_DIR {}",
            out_dir.display()
        ));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT_DIR: &str = "/repo/target/debug/build/zstd-sys-0123/out";

    /// The output of a real `zstd-sys` 2.1.2 build, shortened.
    fn vendored() -> String {
        format!(
            "cargo:rerun-if-env-changed=ZSTD_SYS_USE_PKG_CONFIG\n\
             CC_x86_64-unknown-linux-gnu = None\n\
             cargo:rerun-if-env-changed=CFLAGS\n\
             cargo:rustc-link-lib=static=zstd\n\
             cargo:rustc-link-search=native={OUT_DIR}\n\
             cargo:root={OUT_DIR}\n\
             cargo:include=/home/u/.cargo/registry/src/x/zstd-sys-2.1.2+zstd.1.5.7/zstd/lib\n"
        )
    }

    fn problems(output: &str) -> Vec<String> {
        link_problems("output", &directives(output), Path::new(OUT_DIR))
    }

    #[test]
    fn the_vendored_build_passes() {
        assert_eq!(
            directives(&vendored()),
            vec![
                Directive::Lib("static=zstd".to_owned()),
                Directive::Search(format!("native={OUT_DIR}")),
            ]
        );
        assert_eq!(problems(&vendored()), Vec::<String>::new());
    }

    #[test]
    fn the_new_directive_syntax_is_read_too() {
        let output =
            format!("cargo::rustc-link-lib=static=zstd\ncargo::rustc-link-search={OUT_DIR}/lib\n");
        assert_eq!(problems(&output), Vec::<String>::new());
    }

    #[test]
    fn a_system_libzstd_through_pkg_config_fails() {
        let output = "cargo:rerun-if-env-changed=ZSTD_SYS_USE_PKG_CONFIG\n\
                      cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu\n\
                      cargo:rustc-link-lib=zstd\n\
                      cargo:include=/usr/include\n";
        let found = problems(output);
        // A dynamic zstd, a /usr search path, no static zstd, no OUT_DIR search.
        assert_eq!(found.len(), 4, "{found:?}");
    }

    #[test]
    fn a_system_search_path_beside_the_vendored_library_fails() {
        for path in [
            "/usr/lib",
            "/opt/homebrew/lib",
            "/lib64",
            "/repo/target/debug/build",
        ] {
            let output = format!("{}cargo:rustc-link-search=native={path}\n", vendored());
            let found = problems(&output);
            assert_eq!(found.len(), 1, "{path}: {found:?}");
            assert!(found[0].contains(path), "{found:?}");
        }
        let bare = format!("{}cargo:rustc-link-search=/usr/local/lib\n", vendored());
        assert_eq!(problems(&bare).len(), 1, "a search path without a kind");
    }

    #[test]
    fn a_dynamic_or_extra_library_fails() {
        let dynamic =
            format!("cargo:rustc-link-lib=dylib=zstd\ncargo:rustc-link-search=native={OUT_DIR}\n");
        assert_eq!(problems(&dynamic).len(), 2, "dylib, and no static zstd");
        let extra = format!("{}cargo:rustc-link-lib=static=zstd_static\n", vendored());
        assert_eq!(problems(&extra).len(), 1, "a second library");
    }

    #[test]
    fn linker_arguments_fail() {
        for line in [
            "cargo:rustc-link-arg=-L/usr/lib",
            "cargo::rustc-link-arg-bins=-lzstd",
            "cargo:rustc-flags=-l zstd -L /usr/lib",
        ] {
            let output = format!("{}{line}\n", vendored());
            assert_eq!(problems(&output).len(), 1, "{line}");
        }
    }

    #[test]
    fn empty_output_fails() {
        assert_eq!(problems("").len(), 2, "no library and no search path");
        assert_eq!(
            problems("CC = None\ncargo:root=/x\n").len(),
            2,
            "only non-link lines"
        );
    }
}
