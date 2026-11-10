//! The FastCDC masks for an average of 256 KiB at normalisation level 2 (FS-52).
//!
//! `fastcdc::v2020::select_masks` picks them as `MASKS[bits ± 2]` with `bits` the rounded
//! base-2 logarithm of the average, computed through `f64`; for 256 KiB, `bits` is 18. They are
//! written out here so no float is involved, and a test checks them against the crate.

/// The strict mask, used below the average size: `MASKS[20]`, 20 bits set.
pub const MASK_S: u64 = 0x0000_d917_4753_7000;

/// The loose mask, used from the average size up to the maximum: `MASKS[16]`, 16 bits set.
pub const MASK_L: u64 = 0x0000_d903_0353_7000;

#[cfg(test)]
mod tests {
    use fastcdc::v2020::{self, Normalization};

    use super::*;
    use crate::limits::AVG_CHUNK;

    #[test]
    fn the_masks_are_those_fastcdc_selects() {
        assert_eq!(
            (MASK_S, MASK_L),
            v2020::select_masks(AVG_CHUNK, Normalization::Level2)
        );
        assert_eq!(MASK_S, v2020::MASKS[20]);
        assert_eq!(MASK_L, v2020::MASKS[16]);
        assert_eq!((MASK_S.count_ones(), MASK_L.count_ones()), (20, 16));
    }
}
