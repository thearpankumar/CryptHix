//! Cipher suites (format spec section 4.2).

use crate::format_error::FormatError;

/// A cipher suite ID, the `suite` field of the preamble.
///
/// Format 0 has exactly one suite, `0x0001` (FS-05).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SuiteId(u16);

impl SuiteId {
    /// Suite `0x0001`: XChaCha20-Poly1305 inside CX-AEAD, HKDF-SHA-256, BLAKE3, Ed25519 and
    /// Argon2id.
    pub const SUITE_0001: Self = Self(0x0001);

    /// Checks a raw suite ID against format 0.
    ///
    /// # Errors
    ///
    /// [`FormatError::UnsupportedSuite`] for any suite other than `0x0001` (FS-05, FS-16).
    pub fn try_from_code(code: u16) -> Result<Self, FormatError> {
        if code == Self::SUITE_0001.0 {
            Ok(Self::SUITE_0001)
        } else {
            Err(FormatError::UnsupportedSuite)
        }
    }

    /// The raw value.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for SuiteId {
    type Error = FormatError;

    fn try_from(code: u16) -> Result<Self, Self::Error> {
        Self::try_from_code(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_suite_one_is_accepted() {
        assert_eq!(SuiteId::try_from_code(1), Ok(SuiteId::SUITE_0001));
        assert_eq!(
            SuiteId::try_from_code(0),
            Err(FormatError::UnsupportedSuite)
        );
        assert_eq!(
            SuiteId::try_from_code(2),
            Err(FormatError::UnsupportedSuite)
        );
    }
}
