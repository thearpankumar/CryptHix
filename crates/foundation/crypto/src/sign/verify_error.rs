//! Why a signature was not verified.

use std::error::Error;
use std::fmt;

use crypthix_types::format_error::FormatError;

use crate::secure_mem::MemError;

/// A signature was not verified: it is invalid, or its input had no memory to be checked in.
///
/// As with [`KeyError`](crate::key::KeyError), [`Display`](fmt::Display) says which of the two
/// it was and [`source`](Error::source) returns the underlying error, so a report that walks the
/// chain prints each message once.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum VerifyError {
    /// [`FormatError::Signature`]: the signature is invalid, malleable or not canonical
    /// (FS-14).
    Format(FormatError),
    /// No protected memory for the signature input (O1), so the signature was not checked.
    /// Reported apart from `Signature`, so memory pressure never looks like a forgery.
    Memory(MemError),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VerifyError::Format(_) => "the signature does not verify",
            VerifyError::Memory(_) => "no protected memory for the signature input",
        })
    }
}

impl Error for VerifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            VerifyError::Format(error) => Some(error),
            VerifyError::Memory(error) => Some(error),
        }
    }
}

impl From<FormatError> for VerifyError {
    fn from(error: FormatError) -> Self {
        VerifyError::Format(error)
    }
}

impl From<MemError> for VerifyError {
    fn from(error: MemError) -> Self {
        VerifyError::Memory(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each message appears once in the chain: the variant's own, then the source's.
    #[test]
    fn display_names_the_kind_and_source_is_the_cause() {
        let cases: [(VerifyError, &str, &dyn Error); 2] = [
            (
                VerifyError::from(FormatError::Signature),
                "the signature does not verify",
                &FormatError::Signature,
            ),
            (
                VerifyError::from(MemError::MapFailed),
                "no protected memory for the signature input",
                &MemError::MapFailed,
            ),
        ];
        for (error, message, cause) in cases {
            assert_eq!(error.to_string(), message);
            let source = error.source().expect("every variant wraps its cause");
            assert_eq!(source.to_string(), cause.to_string(), "{message}");
        }
    }
}
