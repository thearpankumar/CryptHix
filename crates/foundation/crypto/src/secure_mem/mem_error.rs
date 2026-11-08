//! Why protected memory could not be had.

use std::error::Error;
use std::fmt;

use crate::secure_mem::Level;

/// No key or plaintext buffer was made, because no protected memory for it could be had.
///
/// Keys report [`BelowMinimum`](MemError::BelowMinimum),
/// [`PoolExhausted`](MemError::PoolExhausted), [`MapFailed`](MemError::MapFailed) and, for an
/// absurd [`Config::with_pages_per_arena`](crate::secure_mem::Config::with_pages_per_arena),
/// [`TooLarge`](MemError::TooLarge); [`init`](crate::secure_mem::init) also
/// [`AlreadyInitialised`](MemError::AlreadyInitialised). Plaintext buffers, which have no
/// minimum and are not in the pool, report only `MapFailed` and `TooLarge`.
///
/// The message names no address, key or plaintext.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MemError {
    /// The best level the system gave is below the minimum set with
    /// [`Config::with_minimum`](crate::secure_mem::Config::with_minimum).
    BelowMinimum {
        /// The best level available.
        got: Level,
        /// The minimum the app asked for.
        want: Level,
    },
    /// Every key slot is in use and the pool has reached
    /// [`Config::with_max_pages`](crate::secure_mem::Config::with_max_pages).
    PoolExhausted,
    /// The kernel refused every level the key arena or buffer may get, as when the process is
    /// out of address space or of memory areas (`vm.max_map_count`).
    /// [`Status::reason`](crate::secure_mem::Status::reason) or
    /// [`Status::buffer_reason`](crate::secure_mem::Status::buffer_reason) says why.
    MapFailed,
    /// The memory asked for, with its two guard pages, would pass `isize::MAX` bytes, so no
    /// mapping was tried and no reason is recorded.
    TooLarge,
    /// [`init`](crate::secure_mem::init) was called after the pool was set up, by an earlier
    /// `init`, the first key or the first plaintext buffer.
    AlreadyInitialised,
}

impl fmt::Display for MemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemError::BelowMinimum { got, want } => {
                write!(f, "protected memory is {got}, below the minimum {want}")
            }
            MemError::PoolExhausted => f.write_str("every protected key slot is in use"),
            MemError::MapFailed => f.write_str("the kernel refused to map protected memory"),
            MemError::TooLarge => f.write_str("the protected memory asked for is too large"),
            MemError::AlreadyInitialised => f.write_str("protected memory is already set up"),
        }
    }
}

impl Error for MemError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_minimum_names_both_levels() {
        let error = MemError::BelowMinimum {
            got: Level::DumpExcluded,
            want: Level::Locked,
        };
        assert_eq!(
            error.to_string(),
            "protected memory is dump-excluded, below the minimum locked"
        );
    }

    #[test]
    fn a_size_past_the_address_space_is_not_a_kernel_refusal() {
        assert_eq!(
            MemError::TooLarge.to_string(),
            "the protected memory asked for is too large"
        );
        assert_ne!(
            MemError::TooLarge.to_string(),
            MemError::MapFailed.to_string()
        );
    }
}
