//! GREASE values (FS-22).
//!
//! GREASE values are reserved and never assigned, so readers that wrongly reject unknown values
//! fail their tests early.

/// Whether `value` is a GREASE value: `0x?A?A` (`0x0A0A`, `0x1A1A`, … `0xFAFA`) or its negation.
///
/// Applies to map keys, in both positive and negative form, and to log kinds. A negative GREASE
/// key is ignored like a positive one, not treated as critical.
#[must_use]
pub const fn is_grease_value(value: i64) -> bool {
    let magnitude = value.unsigned_abs();
    // Both bytes equal and of the form 0x?A.
    magnitude <= 0xFFFF && magnitude & 0x0F0F == 0x0A0A && magnitude >> 8 == magnitude & 0xFF
}

/// Whether `bit` is a GREASE bit number (42, 58 or 63) in a capability or feature bit set.
#[must_use]
pub const fn is_grease_bit(bit: u32) -> bool {
    matches!(bit, 42 | 58 | 63)
}

/// The GREASE bits as a mask over a 64-bit set.
pub const GREASE_BITS: u64 = (1 << 42) | (1 << 58) | (1 << 63);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixteen_values_in_each_sign() {
        let positive: Vec<i64> = (0..=0xFFFF)
            .filter(|value| is_grease_value(*value))
            .collect();
        let expected: Vec<i64> = (0..16).map(|high| high * 0x1010 + 0x0A0A).collect();
        assert_eq!(positive, expected);
        for value in expected {
            assert!(is_grease_value(-value), "{value:#x} negated");
        }
    }

    #[test]
    fn near_misses_are_not_grease() {
        for value in [0, 0x0A0B, 0x0B0A, 0x0A, 0x1A0A, 0x1_0A0A, -0x0A0B] {
            assert!(!is_grease_value(value), "{value:#x}");
        }
    }

    #[test]
    fn grease_bits() {
        assert!(
            is_grease_bit(42) && is_grease_bit(58) && is_grease_bit(63),
            "FS-22 bits"
        );
        assert!(
            !is_grease_bit(0) && !is_grease_bit(41),
            "ordinary bits are not GREASE"
        );
        assert_eq!(GREASE_BITS.count_ones(), 3);
    }
}
