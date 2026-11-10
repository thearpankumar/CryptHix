//! Why a chunk or meta blob was not written.

use std::error::Error;
use std::fmt;

use crypthix_crypto::cx_aead::SealError;
use crypthix_crypto::key::KeyError;
use crypthix_crypto::random::RandomError;
use crypthix_crypto::secure_mem::MemError;
use crypthix_types::format_error::FormatError;

use crate::compress::CompressError;

/// Nothing was written: no protected memory, no randomness, a failed seal or compression, or
/// input that breaks a format rule.
///
/// A zstd failure is always reported here, never answered by storing the chunk uncompressed,
/// so a broken compressor cannot change what is written behind the caller's back.
///
/// The failure of a [`KeyError`], as from [`ChunkKeys::derive`](crate::blob::ChunkKeys::derive),
/// converts with `?`: its `Random`, `Memory` and `Format` kinds to the same kinds here, anything
/// else to [`WriteError::Key`].
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum WriteError {
    /// No protected memory for a plaintext buffer or a key (O1).
    Memory(MemError),
    /// The kernel could not supply a random blob ID (FS-01).
    Random(RandomError),
    /// The CX-AEAD seal failed.
    Seal(SealError),
    /// zstd itself failed (FS-53): it could not make a context, refused a parameter, failed
    /// to compress, or is not the libzstd version FS-53 pins. Named like
    /// [`ReadError::Zstd`](crate::error::ReadError::Zstd).
    Zstd(CompressError),
    /// The input breaks a format rule: `Limit` for a chunk or payload over 1 MiB, `ZeroValue`
    /// for an all-zero ID.
    Format(FormatError),
    /// A key could not be derived for a reason none of `Random`, `Memory` and `Format` names.
    Key(KeyError),
    /// An [`ObjectSealer`](crate::blob::ObjectSealer) was given a chunk that is not the next
    /// chunk of an object of its shape, a chunk identified by another sealer, or a chunk with a
    /// random blob ID to reuse; or it was finished before the object's last chunk. Nothing was
    /// sealed and the sealer did not move on. Any blob it sealed before a failed `finish` must
    /// not be stored.
    Sequence,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WriteError::Memory(_) => "no protected memory to write the chunk",
            WriteError::Random(_) => "no randomness for a blob ID",
            WriteError::Seal(_) => "the blob could not be sealed",
            WriteError::Zstd(_) => "zstd failed",
            WriteError::Format(_) => "the input breaks a format rule",
            WriteError::Key(_) => "a key could not be derived",
            WriteError::Sequence => "the chunks sealed are not those of the object, in order",
        })
    }
}

impl Error for WriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            WriteError::Memory(error) => Some(error),
            WriteError::Random(error) => Some(error),
            WriteError::Seal(error) => Some(error),
            WriteError::Zstd(error) => Some(error),
            WriteError::Format(error) => Some(error),
            WriteError::Key(error) => Some(error),
            WriteError::Sequence => None,
        }
    }
}

impl From<MemError> for WriteError {
    fn from(error: MemError) -> Self {
        WriteError::Memory(error)
    }
}

impl From<RandomError> for WriteError {
    fn from(error: RandomError) -> Self {
        WriteError::Random(error)
    }
}

impl From<SealError> for WriteError {
    fn from(error: SealError) -> Self {
        WriteError::Seal(error)
    }
}

impl From<CompressError> for WriteError {
    fn from(error: CompressError) -> Self {
        WriteError::Zstd(error)
    }
}

impl From<FormatError> for WriteError {
    fn from(error: FormatError) -> Self {
        WriteError::Format(error)
    }
}

impl From<KeyError> for WriteError {
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::Random(error) => WriteError::Random(error),
            KeyError::Memory(error) => WriteError::Memory(error),
            KeyError::Format(error) => WriteError::Format(error),
            other => WriteError::Key(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_the_kind_and_source_is_the_cause() {
        let key = KeyError::Random(RandomError);
        let cases: [(WriteError, &dyn Error); 6] = [
            (MemError::MapFailed.into(), &MemError::MapFailed),
            (RandomError.into(), &RandomError),
            (SealError::TooLong.into(), &SealError::TooLong),
            (CompressError::Context.into(), &CompressError::Context),
            (FormatError::Limit.into(), &FormatError::Limit),
            (WriteError::Key(key), &key),
        ];
        let mut messages = Vec::new();
        for (error, cause) in cases {
            let source = error.source().expect("every variant wraps its cause");
            assert_eq!(source.to_string(), cause.to_string());
            messages.push(error.to_string());
        }
        assert_eq!(WriteError::Sequence.source().map(ToString::to_string), None);
        messages.push(WriteError::Sequence.to_string());
        messages.sort();
        messages.dedup();
        assert_eq!(messages.len(), 7, "two kinds share a message");
    }

    #[test]
    fn a_key_error_keeps_its_kind() {
        assert_eq!(
            WriteError::from(KeyError::Random(RandomError)),
            WriteError::Random(RandomError)
        );
        assert_eq!(
            WriteError::from(KeyError::Memory(MemError::MapFailed)),
            WriteError::Memory(MemError::MapFailed)
        );
        assert_eq!(
            WriteError::from(KeyError::Format(FormatError::ZeroValue)),
            WriteError::Format(FormatError::ZeroValue)
        );
    }
}
