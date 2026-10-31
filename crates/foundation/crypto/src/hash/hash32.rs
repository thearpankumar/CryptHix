//! A 32-byte hash, MAC or commitment value with constant-time equality.

use std::fmt;

use subtle::ConstantTimeEq;

use crypthix_types::format_error::FormatError;

use crate::key::sealed::{Sealed, Token};

/// A 32-byte output of `H`, `MAC` or a commitment.
///
/// Equality runs in constant time, since comparing a hash, MAC or commitment can decide
/// authenticity (FS-15). The value is not secret: it can be copied and printed.
#[derive(Clone, Copy)]
pub struct Hash32([u8; 32]);

impl Hash32 {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Wraps raw bytes, for example a hash read from a file.
    ///
    /// # Errors
    ///
    /// [`FormatError::ZeroValue`] if every byte is zero (FS-03).
    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, FormatError> {
        if bytes == [0u8; 32] {
            Err(FormatError::ZeroValue)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Wraps the output of a primitive, which is never all zero in practice.
    pub(crate) const fn from_output(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The first `N` bytes, for truncated uses such as a 16-byte `vault_id` or a 24-byte nonce.
    #[must_use]
    pub fn prefix<const N: usize>(&self) -> [u8; N] {
        const { assert!(N <= Self::LEN, "a prefix is at most 32 bytes") };
        let mut out = [0u8; N];
        out.copy_from_slice(&self.0[..N]);
        out
    }
}

impl PartialEq for Hash32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Hash32 {}

/// `root_commit` is the one KDF output that is a public value, not a key (FS-38, FS-43).
impl Sealed for Hash32 {
    fn from_material(bytes: [u8; 32], _: Token) -> Self {
        Self(bytes)
    }

    fn material(&self, _: Token) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hash32(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_rejected() {
        assert_eq!(
            Hash32::try_from_bytes([0; 32]).err(),
            Some(FormatError::ZeroValue)
        );
        assert!(
            Hash32::try_from_bytes([1; 32]).is_ok(),
            "a non-zero hash is valid"
        );
    }

    #[test]
    fn equality_compares_every_byte() {
        let mut other = [7u8; 32];
        assert_eq!(Hash32::from_output([7; 32]), Hash32::from_output(other));
        other[31] = 8;
        assert_ne!(Hash32::from_output([7; 32]), Hash32::from_output(other));
    }

    #[test]
    fn prefix_takes_the_first_bytes() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[23] = 2;
        let prefix: [u8; 24] = Hash32::from_output(bytes).prefix();
        assert_eq!(prefix[0], 1);
        assert_eq!(prefix[23], 2);
    }
}
