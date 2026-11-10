//! The store-raw rule (FS-53).

/// Whether a zstd frame of `frame_len` bytes is kept for a chunk of `plain_len` bytes: only if
/// `16 × frame_len ≤ 15 × plain_len`, so compression saves at least 1/16. Otherwise the chunk is
/// stored raw (FS-53).
///
/// ```
/// use crypthix_core::compress::keep_compressed;
///
/// assert!(keep_compressed(15, 16));
/// assert!(!keep_compressed(16, 16));
/// ```
#[must_use]
pub fn keep_compressed(frame_len: u64, plain_len: u64) -> bool {
    // In u128, so no length can overflow.
    u128::from(frame_len) * 16 <= u128::from(plain_len) * 15
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_boundary_is_fifteen_sixteenths() {
        assert!(keep_compressed(960, 1_024));
        assert!(!keep_compressed(961, 1_024));
        assert!(keep_compressed(983_040, 1 << 20));
        assert!(!keep_compressed(983_041, 1 << 20));
        assert!(keep_compressed(0, 0), "an empty frame of nothing");
        assert!(!keep_compressed(9, 0));
        // Lengths whose products pass u64::MAX.
        assert!(keep_compressed(15 << 59, 1 << 63));
        assert!(!keep_compressed((15 << 59) + 1, 1 << 63));
    }
}
