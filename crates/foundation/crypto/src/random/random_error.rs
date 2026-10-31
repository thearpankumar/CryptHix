//! The error of a failed draw from the kernel.

use std::error::Error;
use std::fmt;

/// The kernel could not supply randomness.
///
/// No key, nonce or ID is produced in that case; callers stop rather than fall back to a weaker
/// source (FS-01).
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RandomError;

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the kernel random number generator failed")
    }
}

impl Error for RandomError {}
