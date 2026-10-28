//! Format versions (format spec section 6).

use crate::format_error::FormatError;

/// A format version, the `fmt` field of the preamble.
///
/// This build reads and writes format 0 only and never falls back to another (FS-16).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct FormatVersion(u16);

impl FormatVersion {
    /// Format 0, the current draft format.
    pub const V0: Self = Self(0x0000);

    /// Every format version this build supports.
    pub const SUPPORTED: &'static [Self] = &[Self::V0];

    /// Checks a raw format version.
    ///
    /// # Errors
    ///
    /// [`FormatError::UnsupportedFormat`] for any version this build does not support (FS-16).
    pub fn try_from_code(code: u16) -> Result<Self, FormatError> {
        let version = Self(code);
        if Self::SUPPORTED.contains(&version) {
            Ok(version)
        } else {
            Err(FormatError::UnsupportedFormat)
        }
    }

    /// The raw value.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for FormatVersion {
    type Error = FormatError;

    fn try_from(code: u16) -> Result<Self, Self::Error> {
        Self::try_from_code(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_format_zero_is_supported() {
        assert_eq!(FormatVersion::try_from_code(0), Ok(FormatVersion::V0));
        assert_eq!(
            FormatVersion::try_from_code(1),
            Err(FormatError::UnsupportedFormat)
        );
        assert_eq!(
            FormatVersion::try_from_code(0x0a0a),
            Err(FormatError::UnsupportedFormat)
        );
    }
}
