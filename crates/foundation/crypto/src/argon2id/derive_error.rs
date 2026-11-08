//! Why a passphrase derivation failed.

use std::error::Error;
use std::fmt;

use crate::secure_mem::MemError;

/// An Argon2id derivation produced no key.
///
/// As with [`KeyError`](crate::key::KeyError), [`Display`](fmt::Display) gives this error's own
/// message and [`source`](Error::source) the underlying [`MemError`], never both.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DeriveError {
    /// The salt is all zero (FS-03); callers report it as `ZeroValue`.
    ZeroSalt,
    /// The Argon2id working memory the parameters ask for could not be allocated. The
    /// parameters passed the ceilings of FS-41, so the device is short of memory, not the file
    /// malicious.
    ArgonMemory,
    /// No protected memory at the required level for the derived key (O1).
    KeyMemory(MemError),
}

impl From<MemError> for DeriveError {
    fn from(error: MemError) -> Self {
        DeriveError::KeyMemory(error)
    }
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeriveError::ZeroSalt => f.write_str("all-zero Argon2id salt"),
            DeriveError::ArgonMemory => f.write_str("not enough memory for Argon2id"),
            DeriveError::KeyMemory(_) => f.write_str("no protected memory for the derived key"),
        }
    }
}

impl Error for DeriveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DeriveError::KeyMemory(error) => Some(error),
            DeriveError::ZeroSalt | DeriveError::ArgonMemory => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_key_memory_has_a_source_and_it_is_not_printed_twice() {
        let error = DeriveError::from(MemError::PoolExhausted);
        assert_eq!(error.to_string(), "no protected memory for the derived key");
        assert_eq!(
            error.source().map(ToString::to_string),
            Some(MemError::PoolExhausted.to_string())
        );
        assert_eq!(
            DeriveError::ArgonMemory.to_string(),
            "not enough memory for Argon2id"
        );
        assert!(DeriveError::ZeroSalt.source().is_none());
        assert!(DeriveError::ArgonMemory.source().is_none());
    }
}
