//! Why a chunk or meta blob did not open.

use std::error::Error;
use std::fmt;

use crypthix_crypto::cx_aead::OpenError;
use crypthix_crypto::key::KeyError;
use crypthix_crypto::secure_mem::MemError;
use crypthix_types::format_error::FormatError;

use crate::compress::CompressError;

/// A blob did not open: it breaks a format rule, there was no protected memory for its
/// plaintext, zstd itself failed, or a key could not be derived.
///
/// A blob that is not what its reference says is always [`ReadError::Format`], with the first
/// failing check of FS-93: `Decompress`, `Decrypt`, `Padding`, `Limit` or `Binding`. A frame
/// that does not decode is such a check, `FormatError::Decompress`; [`ReadError::Zstd`] is zstd
/// failing for a reason of its own. The kinds other than `Format` depend only on the reader's
/// own resources, so they never look like tampering.
///
/// The failure of a [`KeyError`], as from [`ChunkKeys::derive`](crate::blob::ChunkKeys::derive),
/// converts with `?`: its `Format` and `Memory` kinds to the same kinds here, anything else to
/// [`ReadError::Key`].
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ReadError {
    /// The blob breaks a format rule (section 19).
    Format(FormatError),
    /// No protected memory for the plaintext (O1).
    Memory(MemError),
    /// zstd itself failed: it could not make or reset a decompression context, ran out of
    /// memory while decoding, or is not the libzstd version FS-53 pins
    /// ([`CompressError::Version`]). Not a format error: it depends on the reader, not on the
    /// frame. Named like [`WriteError::Zstd`](crate::error::WriteError::Zstd).
    Zstd(CompressError),
    /// A key could not be derived for a reason neither `Format` nor `Memory` names.
    Key(KeyError),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReadError::Format(_) => "the blob did not open",
            ReadError::Memory(_) => "no protected memory for the plaintext",
            ReadError::Zstd(_) => "zstd failed",
            ReadError::Key(_) => "a key could not be derived",
        })
    }
}

impl Error for ReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ReadError::Format(error) => Some(error),
            ReadError::Memory(error) => Some(error),
            ReadError::Zstd(error) => Some(error),
            ReadError::Key(error) => Some(error),
        }
    }
}

impl From<FormatError> for ReadError {
    fn from(error: FormatError) -> Self {
        ReadError::Format(error)
    }
}

impl From<MemError> for ReadError {
    fn from(error: MemError) -> Self {
        ReadError::Memory(error)
    }
}

impl From<OpenError> for ReadError {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Format(error) => ReadError::Format(error),
            OpenError::Memory(error) => ReadError::Memory(error),
            // A kind added later is still a failed open; the opaque `Decrypt` reveals nothing.
            _ => ReadError::Format(FormatError::Decrypt),
        }
    }
}

impl From<KeyError> for ReadError {
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::Format(error) => ReadError::Format(error),
            KeyError::Memory(error) => ReadError::Memory(error),
            other => ReadError::Key(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use crypthix_crypto::random::RandomError;

    use super::*;

    #[test]
    fn display_names_the_kind_and_source_is_the_cause() {
        let cases: [(ReadError, &dyn Error); 4] = [
            (FormatError::Binding.into(), &FormatError::Binding),
            (MemError::MapFailed.into(), &MemError::MapFailed),
            (
                ReadError::Zstd(CompressError::Context),
                &CompressError::Context,
            ),
            (
                ReadError::Key(KeyError::Random(RandomError)),
                &KeyError::Random(RandomError),
            ),
        ];
        let mut messages = Vec::new();
        for (error, cause) in cases {
            let source = error.source().expect("every variant wraps its cause");
            assert_eq!(source.to_string(), cause.to_string());
            messages.push(error.to_string());
        }
        messages.sort();
        messages.dedup();
        assert_eq!(messages.len(), 4, "two kinds share a message");
    }

    #[test]
    fn a_key_error_keeps_its_kind() {
        assert_eq!(
            ReadError::from(KeyError::Format(FormatError::ZeroValue)),
            ReadError::Format(FormatError::ZeroValue)
        );
        assert_eq!(
            ReadError::from(KeyError::Memory(MemError::MapFailed)),
            ReadError::Memory(MemError::MapFailed)
        );
        assert_eq!(
            ReadError::from(KeyError::Random(RandomError)),
            ReadError::Key(KeyError::Random(RandomError))
        );
    }

    #[test]
    fn an_open_error_keeps_its_kind() {
        assert_eq!(
            ReadError::from(OpenError::Format(FormatError::Decrypt)),
            ReadError::Format(FormatError::Decrypt)
        );
        assert_eq!(
            ReadError::from(OpenError::Memory(MemError::MapFailed)),
            ReadError::Memory(MemError::MapFailed)
        );
    }
}
