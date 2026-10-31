//! The all-zero check of FS-03 for keys and salts.

use subtle::ConstantTimeEq;

use crypthix_types::format_error::FormatError;

/// Rejects 32 all-zero bytes, comparing in constant time since the bytes may be secret.
///
/// # Errors
///
/// [`FormatError::ZeroValue`] for an all-zero value (FS-03).
pub(crate) fn check_nonzero(bytes: &[u8; 32]) -> Result<(), FormatError> {
    if bool::from(bytes.ct_eq(&[0u8; 32])) {
        Err(FormatError::ZeroValue)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_all_zero_fails() {
        assert_eq!(check_nonzero(&[0; 32]), Err(FormatError::ZeroValue));
        let mut last = [0u8; 32];
        last[31] = 1;
        assert_eq!(check_nonzero(&last), Ok(()));
    }
}
