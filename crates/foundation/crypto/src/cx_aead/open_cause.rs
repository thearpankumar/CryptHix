//! The inner causes of a failed open, visible outside the crate only for TV-05 (FS-28).

use crypthix_types::format_error::FormatError;

use crate::cx_aead::OpenError;
use crate::secure_mem::MemError;

/// Why an open failed, naming which check it failed.
#[cfg_attr(
    not(feature = "vectors"),
    expect(unreachable_pub, reason = "public only with `vectors`, for TV-05")
)]
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OpenCause {
    /// Shorter than the 72-byte overhead.
    Truncated,
    /// An all-zero nonce, which FS-03 forbids; no seal produces one.
    ZeroNonce,
    /// The commitment does not match: the key, nonce or AAD changed.
    Commitment,
    /// The tag does not match: the ciphertext or tag changed.
    AeadTag,
    /// The commitment held but no protected memory for the plaintext could be had (O1). Not a
    /// check of the input, so no test vector expects it.
    Memory(MemError),
}

impl OpenCause {
    /// The stable name, as used in test vectors.
    #[cfg(feature = "vectors")]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            OpenCause::Truncated => "Truncated",
            OpenCause::ZeroNonce => "ZeroValue",
            OpenCause::Commitment => "Commitment",
            OpenCause::AeadTag => "AeadTag",
            OpenCause::Memory(_) => "Memory",
        }
    }

    /// The error every caller outside this crate sees: both AEAD causes become the one opaque
    /// `Decrypt` (FS-28). Memory stays apart, so running out of it never looks like tampering.
    pub(crate) const fn opaque(self) -> OpenError {
        match self {
            OpenCause::Truncated => OpenError::Format(FormatError::Truncated),
            OpenCause::ZeroNonce => OpenError::Format(FormatError::ZeroValue),
            OpenCause::Commitment | OpenCause::AeadTag => OpenError::Format(FormatError::Decrypt),
            OpenCause::Memory(error) => OpenError::Memory(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_aead_causes_become_decrypt() {
        let cases = [
            (OpenCause::Truncated, FormatError::Truncated.into()),
            (OpenCause::ZeroNonce, FormatError::ZeroValue.into()),
            (OpenCause::Commitment, FormatError::Decrypt.into()),
            (OpenCause::AeadTag, FormatError::Decrypt.into()),
            (
                OpenCause::Memory(MemError::MapFailed),
                OpenError::Memory(MemError::MapFailed),
            ),
        ];
        for (cause, opaque) in cases {
            assert_eq!(cause.opaque(), opaque, "{cause:?}");
        }
    }
}
