//! The sizes and masks one cut uses.

use crate::chunk::{MASK_L, MASK_S};
use crate::limits::{AVG_CHUNK, MAX_CHUNK, MIN_CHUNK};

/// Minimum, average and maximum chunk size with their masks. Format 0 has exactly one set,
/// [`ChunkParams::FORMAT_0`]; tests use scaled-down sets so properties run on small inputs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ChunkParams {
    pub(crate) min: usize,
    pub(crate) avg: usize,
    pub(crate) max: usize,
    pub(crate) mask_s: u64,
    pub(crate) mask_l: u64,
}

impl ChunkParams {
    /// 64 KiB, 256 KiB and 1 MiB with the level 2 masks for 256 KiB (FS-52).
    pub(crate) const FORMAT_0: Self = Self {
        min: MIN_CHUNK,
        avg: AVG_CHUNK,
        max: MAX_CHUNK,
        mask_s: MASK_S,
        mask_l: MASK_L,
    };

    /// Scaled-down sizes for tests and the `chunker` fuzz target: 64, 256 and 1,024 bytes with
    /// the level 2 masks fastcdc selects for a 256-byte average, `MASKS[10]` and `MASKS[6]`. Not
    /// a format 0 set: no object is ever cut with it.
    pub(crate) const SCALED: Self = Self {
        min: 64,
        avg: 256,
        max: 1024,
        mask_s: 0x0000_5900_0353_0000,
        mask_l: 0x0000_0000_0180_3110,
    };
}

#[cfg(test)]
mod tests {
    use fastcdc::v2020::{self, Normalization};

    use super::*;

    #[test]
    fn the_scaled_masks_are_those_fastcdc_selects() {
        let scaled = ChunkParams::SCALED;
        assert_eq!(
            (scaled.mask_s, scaled.mask_l),
            v2020::select_masks(scaled.avg, Normalization::Level2)
        );
    }
}
