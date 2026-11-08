//! Why a key could not be made.

use std::error::Error;
use std::fmt;

use crypthix_types::format_error::FormatError;

use crate::random::RandomError;
use crate::secure_mem::MemError;

/// No key was made: no randomness, no protected memory, or bytes that are not a key.
///
/// [`Display`](fmt::Display) says which of the three it was, and [`source`](Error::source)
/// returns the underlying error, so a report that walks the chain prints each message once
/// (the convention of [`std::error::Error`]).
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum KeyError {
    /// The kernel could not supply randomness (FS-01).
    Random(RandomError),
    /// No protected memory at the required level (O1). Reported apart from
    /// [`FormatError::Decrypt`], so running out of memory never looks like tampering; the slot
    /// is taken before anything is decrypted, so this does not depend on the input.
    Memory(MemError),
    /// The bytes are not a valid key, or a wrap did not open.
    Format(FormatError),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::Random(_) => "no randomness for the key",
            KeyError::Memory(_) => "no protected memory for the key",
            KeyError::Format(_) => "the bytes are not a valid key",
        })
    }
}

impl Error for KeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KeyError::Random(error) => Some(error),
            KeyError::Memory(error) => Some(error),
            KeyError::Format(error) => Some(error),
        }
    }
}

impl From<RandomError> for KeyError {
    fn from(error: RandomError) -> Self {
        KeyError::Random(error)
    }
}

impl From<MemError> for KeyError {
    fn from(error: MemError) -> Self {
        KeyError::Memory(error)
    }
}

impl From<FormatError> for KeyError {
    fn from(error: FormatError) -> Self {
        KeyError::Format(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each message appears once in the chain: the variant's own, then the source's.
    #[test]
    fn display_names_the_kind_and_source_is_the_cause() {
        let cases: [(KeyError, &str, &dyn Error); 3] = [
            (
                KeyError::from(RandomError),
                "no randomness for the key",
                &RandomError,
            ),
            (
                KeyError::from(MemError::PoolExhausted),
                "no protected memory for the key",
                &MemError::PoolExhausted,
            ),
            (
                KeyError::from(FormatError::Decrypt),
                "the bytes are not a valid key",
                &FormatError::Decrypt,
            ),
        ];
        for (error, message, cause) in cases {
            assert_eq!(error.to_string(), message);
            let source = error.source().expect("every variant wraps its cause");
            assert_eq!(source.to_string(), cause.to_string(), "{message}");
            assert!(
                !message.contains(&cause.to_string()),
                "{message}: the cause is not printed twice"
            );
        }
    }
}
