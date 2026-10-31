//! Why a seal failed.

use std::error::Error;
use std::fmt;

use crate::random::RandomError;

/// A seal produced nothing.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SealError {
    /// The kernel could not supply the nonce's randomness (FS-01).
    Random,
    /// The plaintext is longer than [`MAX_PLAINTEXT_LEN`](crate::cx_aead::MAX_PLAINTEXT_LEN).
    TooLong,
    /// The AAD label is sealed another way: a key-wrap label outside
    /// [`seal_key`](crate::cx_aead::seal_key), another label inside it, or a nonce kind that
    /// FS-29 does not give that label (synthetic is for shard headers only, and shard headers
    /// are always synthetic).
    WrongLabel,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SealError::Random => "the kernel random number generator failed",
            SealError::TooLong => "plaintext too long to seal",
            SealError::WrongLabel => "this AAD label is sealed another way",
        })
    }
}

impl Error for SealError {}

impl From<RandomError> for SealError {
    fn from(_: RandomError) -> Self {
        SealError::Random
    }
}
