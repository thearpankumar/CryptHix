//! Why a passphrase derivation failed.

use std::error::Error;
use std::fmt;

/// An Argon2id derivation produced no key.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DeriveError {
    /// The salt is all zero (FS-03); callers report it as `ZeroValue`.
    ZeroSalt,
    /// The memory the parameters ask for could not be allocated. The parameters passed the
    /// ceilings of FS-41, so the device is short of memory, not the file malicious.
    OutOfMemory,
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DeriveError::ZeroSalt => "all-zero Argon2id salt",
            DeriveError::OutOfMemory => "not enough memory for Argon2id",
        })
    }
}

impl Error for DeriveError {}
