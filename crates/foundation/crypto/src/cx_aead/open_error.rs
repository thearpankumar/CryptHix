//! The inner causes of a failed open, visible outside the crate only for TV-05 (FS-28).

use crypthix_types::format_error::FormatError;

/// Why an open failed.
#[cfg_attr(
    not(feature = "vectors"),
    expect(unreachable_pub, reason = "public only with `vectors`, for TV-05")
)]
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OpenError {
    /// Shorter than the 72-byte overhead.
    Truncated,
    /// An all-zero nonce, which FS-03 forbids; no seal produces one.
    ZeroNonce,
    /// The commitment does not match: the key, nonce or AAD changed.
    Commitment,
    /// The tag does not match: the ciphertext or tag changed.
    AeadTag,
}

impl OpenError {
    /// The stable name, as used in test vectors.
    #[cfg(feature = "vectors")]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            OpenError::Truncated => "Truncated",
            OpenError::ZeroNonce => "ZeroValue",
            OpenError::Commitment => "Commitment",
            OpenError::AeadTag => "AeadTag",
        }
    }

    /// The error every caller outside this crate sees: both AEAD causes become the one opaque
    /// `Decrypt` (FS-28).
    pub(crate) const fn opaque(self) -> FormatError {
        match self {
            OpenError::Truncated => FormatError::Truncated,
            OpenError::ZeroNonce => FormatError::ZeroValue,
            OpenError::Commitment | OpenError::AeadTag => FormatError::Decrypt,
        }
    }
}
