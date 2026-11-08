//! Why an open failed, as callers see it.

use std::error::Error;
use std::fmt;

use crypthix_types::format_error::FormatError;

use crate::key::KeyError;
use crate::secure_mem::MemError;

/// A sealed field did not open: the input is not a seal under this key and AAD, or the
/// plaintext had no memory.
///
/// As with [`KeyError`], [`Display`](fmt::Display) says which of the two it was and
/// [`source`](Error::source) returns the underlying error, so a report that walks the chain
/// prints each message once.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OpenError {
    /// The input is not a seal under this key and AAD: `Truncated`, `ZeroValue`, or the one
    /// opaque [`FormatError::Decrypt`] for every failed authentication (FS-28).
    Format(FormatError),
    /// The input passed the key commitment, but no protected memory for its plaintext could be
    /// had (O1). Reported apart from `Decrypt`, so running out of memory never looks like
    /// tampering. It is no oracle: only input whose nonce and commitment were made under this
    /// key and AAD gets this far, so it tells the sender nothing about the key that a genuine
    /// commitment did not already.
    Memory(MemError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OpenError::Format(_) => "the sealed field did not open",
            OpenError::Memory(_) => "no protected memory for the plaintext",
        })
    }
}

impl Error for OpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            OpenError::Format(error) => Some(error),
            OpenError::Memory(error) => Some(error),
        }
    }
}

impl From<FormatError> for OpenError {
    fn from(error: FormatError) -> Self {
        OpenError::Format(error)
    }
}

impl From<MemError> for OpenError {
    fn from(error: MemError) -> Self {
        OpenError::Memory(error)
    }
}

impl From<OpenError> for KeyError {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Format(error) => KeyError::Format(error),
            OpenError::Memory(error) => KeyError::Memory(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each message appears once in the chain: the variant's own, then the source's.
    #[test]
    fn display_names_the_kind_and_source_is_the_cause() {
        let cases: [(OpenError, &str, &dyn Error); 2] = [
            (
                OpenError::from(FormatError::Decrypt),
                "the sealed field did not open",
                &FormatError::Decrypt,
            ),
            (
                OpenError::from(MemError::MapFailed),
                "no protected memory for the plaintext",
                &MemError::MapFailed,
            ),
        ];
        for (error, message, cause) in cases {
            assert_eq!(error.to_string(), message);
            let source = error.source().expect("every variant wraps its cause");
            assert_eq!(source.to_string(), cause.to_string(), "{message}");
        }
    }

    #[test]
    fn a_key_error_keeps_the_kind() {
        assert_eq!(
            KeyError::from(OpenError::Format(FormatError::Decrypt)),
            KeyError::Format(FormatError::Decrypt)
        );
        assert_eq!(
            KeyError::from(OpenError::Memory(MemError::MapFailed)),
            KeyError::Memory(MemError::MapFailed)
        );
    }
}
