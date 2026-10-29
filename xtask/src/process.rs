//! Running child processes, shared by the xtask commands.

use std::env;
use std::ffi::OsString;
use std::process::Command;

/// The cargo that runs this task, so child builds use the project's toolchain.
pub(crate) fn cargo() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

/// Runs a command with inherited output and fails with `failure` if it does not succeed.
pub(crate) fn run_status(command: &mut Command, failure: &str) -> Result<(), String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let status = command
        .status()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(failure.to_owned())
    }
}
