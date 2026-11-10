//! A zstd failure.

use std::error::Error;
use std::fmt;

use zstd_safe::zstd_sys::ZSTD_ErrorCode;

use crate::limits::ZSTD_VERSION;

/// zstd failed for a reason of its own, not because of the input's format.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CompressError {
    /// zstd could not allocate a context.
    Context,
    /// zstd returned an error; its name from `ZSTD_getErrorName`.
    Zstd(&'static str),
    /// The linked libzstd is not the version FS-53 pins
    /// ([`ZSTD_VERSION`](crate::limits::ZSTD_VERSION)); this is the `ZSTD_versionNumber` it
    /// reports. A build fault, not a property of any input.
    Version(u32),
}

impl CompressError {
    /// The error zstd's `code` names.
    pub(crate) fn from_code(code: usize) -> Self {
        CompressError::Zstd(zstd_safe::get_error_name(code))
    }

    /// Whether zstd's `code` is `ZSTD_error_memory_allocation`: zstd ran out of memory, which
    /// says nothing about the input.
    pub(crate) fn is_allocation_failure(code: usize) -> bool {
        // zstd returns an error as the negated `ZSTD_ErrorCode`, as a `size_t`.
        code == (ZSTD_ErrorCode::ZSTD_error_memory_allocation as usize).wrapping_neg()
    }

    /// Checks that the `linked` libzstd version is the one FS-53 pins.
    pub(crate) fn check_version(linked: u32) -> Result<(), Self> {
        if linked == ZSTD_VERSION {
            Ok(())
        } else {
            Err(CompressError::Version(linked))
        }
    }
}

impl fmt::Display for CompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompressError::Context => f.write_str("zstd could not allocate a context"),
            CompressError::Zstd(name) => write!(f, "zstd failed: {name}"),
            CompressError::Version(linked) => write!(
                f,
                "libzstd {linked} is linked, but FS-53 pins {ZSTD_VERSION}"
            ),
        }
    }
}

impl Error for CompressError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn zstd_codes_are_named() {
        // ZSTD_error_dstSize_tooSmall, as a negated size_t.
        let code = 0usize.wrapping_sub(70);
        let error = CompressError::from_code(code);
        assert_eq!(
            error,
            CompressError::Zstd("Destination buffer is too small")
        );
        assert_eq!(
            error.to_string(),
            "zstd failed: Destination buffer is too small"
        );
    }

    #[test]
    fn only_the_allocation_code_is_an_allocation_failure() {
        // ZSTD_error_memory_allocation is 64 and pinned since zstd 1.3.1 (zstd_errors.h).
        assert!(CompressError::is_allocation_failure(
            0usize.wrapping_sub(64)
        ));
        for code in [0, 64, 0usize.wrapping_sub(20), 0usize.wrapping_sub(70)] {
            assert!(!CompressError::is_allocation_failure(code), "{code}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn the_allocation_code_is_the_one_zstd_names() {
        let code = 0usize.wrapping_sub(64);
        assert_eq!(
            CompressError::from_code(code),
            CompressError::Zstd("Allocation error : not enough memory")
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls into libzstd")]
    fn the_pinned_zstd_is_linked() {
        assert_eq!(zstd_safe::version_number(), ZSTD_VERSION);
        assert_eq!(
            CompressError::check_version(zstd_safe::version_number()),
            Ok(())
        );
    }

    #[test]
    fn any_other_version_is_refused() {
        for linked in [0, 10_506, 10_508, 20_000] {
            assert_eq!(
                CompressError::check_version(linked),
                Err(CompressError::Version(linked))
            );
        }
        assert_eq!(
            CompressError::Version(10_508).to_string(),
            "libzstd 10508 is linked, but FS-53 pins 10507"
        );
    }
}
