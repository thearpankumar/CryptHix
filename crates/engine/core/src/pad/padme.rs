//! Padmé (Nikitin et al., PETS 2019), the padding of every inner plaintext (FS-54).

/// The Padmé length of `len`: for `len ≥ 2`, with `E = ⌊log2 len⌋`, `S = ⌊log2 E⌋ + 1` and
/// `z = E − S`, `len` rounded up to a multiple of `2^z`; `len` itself below 2.
///
/// The result is at most 12% above `len` and leaks O(log log n) bits of it. Only integer
/// logarithms are used, so there is no rounding and no special case beyond `len < 2`.
///
/// ```
/// use crypthix_core::pad::padme;
///
/// assert_eq!(padme(9), Some(10));
/// assert_eq!(padme(6 + 1_000), Some(1_024));
/// ```
///
/// Returns `None` only when the rounded length does not fit in a `u64`, for `len` within
/// `2^57` of `u64::MAX`.
#[must_use]
pub const fn padme(len: u64) -> Option<u64> {
    if len < 2 {
        return Some(len);
    }
    let e = len.ilog2();
    let s = e.ilog2() + 1;
    let z = e - s;
    let mask = (1u64 << z) - 1;
    match len.checked_add(mask) {
        Some(sum) => Some(sum & !mask),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::{prop_assert, prop_assert_eq, proptest};

    use super::*;

    #[test]
    fn small_lengths_are_unchanged() {
        for len in 0..=7 {
            assert_eq!(padme(len), Some(len), "{len}");
        }
    }

    #[test]
    fn known_values() {
        // E = 3, S = 2, z = 1: round up to even.
        assert_eq!(padme(9), Some(10));
        assert_eq!(padme(15), Some(16));
        // E = 10, S = 4, z = 6: multiples of 64.
        assert_eq!(padme(1_025), Some(1_088));
        // A full chunk's inner plaintext: E = 20, S = 5, z = 15.
        assert_eq!(padme(6 + (1 << 20)), Some((1 << 20) + (1 << 15)));
        assert_eq!(padme(1 << 20), Some(1 << 20));
    }

    #[test]
    fn the_largest_lengths_overflow_rather_than_wrap() {
        assert_eq!(padme(u64::MAX), None);
        assert_eq!(padme(1 << 63), Some(1 << 63));
        assert_eq!(padme((1 << 63) + 1), Some((1 << 63) + (1 << 57)));
        assert_eq!(padme(u64::MAX - (1 << 57) + 2), None);
        assert_eq!(
            padme(u64::MAX - (1 << 57) + 1),
            Some(u64::MAX - (1 << 57) + 1)
        );
    }

    proptest! {
        #[test]
        fn padme_rounds_up_to_its_step(len in 2u64..(1 << 40)) {
            let padded = padme(len).expect("small lengths fit");
            let e = len.ilog2();
            let step = 1u64 << (e - (e.ilog2() + 1));
            prop_assert!(padded >= len);
            prop_assert!(padded - len < step, "padded past the next step");
            prop_assert_eq!(padded % step, 0);
            // Overhead below 12% once the length is not tiny.
            if len >= 64 {
                prop_assert!((padded - len) * 100 < len * 12);
            }
        }

        #[test]
        fn padme_is_idempotent_and_monotone(len in 0u64..(1 << 40)) {
            let padded = padme(len).expect("small lengths fit");
            prop_assert_eq!(padme(padded), Some(padded));
            prop_assert!(padme(len + 1).expect("fits") >= padded);
        }
    }
}
