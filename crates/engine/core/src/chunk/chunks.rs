//! Cutting data already in memory.

use std::fmt;
use std::iter::FusedIterator;
use std::ops::Range;

use crate::blob::ObjectClass;
use crate::chunk::cut::cut_for;
use crate::chunk::{ChunkParams, GearTable, ObjectShape};

/// The chunks of `data` in an object of a class, as ranges into it, in order (FS-52). Empty
/// data has none. An ordinary object is cut with keyed FastCDC, so data no longer than 64 KiB
/// is one chunk; a secret-class object is cut into 1 MiB chunks and a shorter last one, without
/// reading its bytes.
///
/// ```
/// use crypthix_core::blob::ObjectClass;
/// use crypthix_core::chunk::{Chunks, GearTable};
/// use crypthix_crypto::key::KdfKey;
/// use crypthix_types::id::VaultId;
///
/// let gear = GearTable::derive(&KdfKey::random()?, &VaultId::try_from_bytes([1; 16])?)?;
/// let data = vec![0u8; 3 << 20];
/// let lengths: Vec<usize> =
///     Chunks::new(&gear, ObjectClass::Ordinary, &data).map(|range| range.len()).collect();
/// assert_eq!(lengths, [1 << 20; 3]);
/// let secret = vec![7u8; (5 << 20) / 2];
/// let lengths: Vec<usize> =
///     Chunks::new(&gear, ObjectClass::Secret, &secret).map(|range| range.len()).collect();
/// assert_eq!(lengths, [1 << 20, 1 << 20, 1 << 19]);
/// assert_eq!(Chunks::new(&gear, ObjectClass::Ordinary, &[]).count(), 0);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
#[derive(Clone)]
pub struct Chunks<'a> {
    gear: &'a GearTable,
    class: ObjectClass,
    data: &'a [u8],
    offset: usize,
    params: ChunkParams,
}

impl<'a> Chunks<'a> {
    /// The chunks of `data` in an object of `class`; `gear` is used for the ordinary class
    /// only.
    pub fn new(gear: &'a GearTable, class: ObjectClass, data: &'a [u8]) -> Self {
        Self::with_params(gear, class, data, ChunkParams::FORMAT_0)
    }

    /// The chunks of `data` cut at the scaled-down sizes 64, 256 and 1,024 bytes, with the
    /// level 2 masks for a 256-byte average. Not part of the API and not a format 0 cut: it
    /// lets the `chunker` fuzz target reach every cut-point edge with inputs of a few KiB,
    /// where the format 0 hash is only tested 64 KiB into a chunk.
    #[doc(hidden)]
    pub fn scaled_for_fuzzing(gear: &'a GearTable, class: ObjectClass, data: &'a [u8]) -> Self {
        Self::with_params(gear, class, data, ChunkParams::SCALED)
    }

    /// The chunks of `data` with other sizes and masks, for tests.
    pub(crate) fn with_params(
        gear: &'a GearTable,
        class: ObjectClass,
        data: &'a [u8],
        params: ChunkParams,
    ) -> Self {
        Self {
            gear,
            class,
            data,
            offset: 0,
            params,
        }
    }

    /// The class the chunks are cut for and whether `data` is one chunk or more, which a
    /// writer passes to [`ObjectSealer::new`](crate::blob::ObjectSealer::new) (FS-55). It
    /// depends on the whole data, not on how far the iterator has gone, and costs one cut.
    /// Empty data, which has no chunk to seal, counts as one.
    #[must_use]
    pub fn object_shape(&self) -> ObjectShape {
        let first = cut_for(self.class, self.gear, self.data, &self.params);
        ObjectShape::new(self.class, first >= self.data.len())
    }
}

impl Iterator for Chunks<'_> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Range<usize>> {
        let rest = self.data.get(self.offset..)?;
        let len = cut_for(self.class, self.gear, rest, &self.params);
        if len == 0 {
            return None;
        }
        let start = self.offset;
        self.offset += len;
        Some(start..self.offset)
    }
}

impl FusedIterator for Chunks<'_> {}

/// Prints the class and position only, never the data.
impl fmt::Debug for Chunks<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunks")
            .field("class", &self.class)
            .field("offset", &self.offset)
            .field("len", &self.data.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::{any, prop_assert, prop_assert_eq, proptest};

    use super::*;
    use crate::test_data::gear_table as table;
    use crate::test_data::pseudo_random;

    const CLASSES: [ObjectClass; 2] = [ObjectClass::Ordinary, ObjectClass::Secret];

    #[test]
    fn empty_data_has_no_chunks_and_stays_done() {
        let gear = table(1);
        for class in CLASSES {
            let mut chunks = Chunks::new(&gear, class, &[]);
            assert_eq!(chunks.next(), None);
            assert_eq!(chunks.next(), None);
        }
    }

    #[test]
    fn the_shape_is_single_exactly_when_there_is_at_most_one_chunk() {
        let gear = table(1);
        let params = ChunkParams::SCALED;
        for class in CLASSES {
            for len in [0, 1, params.min, params.max, params.max + 1, 6_000] {
                let data = pseudo_random(3, len);
                let chunks = Chunks::with_params(&gear, class, &data, params);
                let count = chunks.clone().count();
                let shape = chunks.object_shape();
                assert_eq!(shape.is_single(), count <= 1, "{class:?} {len}");
                assert_eq!(shape.class(), class);
            }
        }
    }

    #[test]
    fn debug_shows_no_data() {
        let gear = table(1);
        let mut chunks = Chunks::new(&gear, ObjectClass::Secret, b"secret");
        assert_eq!(
            format!("{chunks:?}"),
            "Chunks { class: Secret, offset: 0, len: 6, .. }"
        );
        assert_eq!(chunks.next(), Some(0..6));
        assert_eq!(
            format!("{chunks:?}"),
            "Chunks { class: Secret, offset: 6, len: 6, .. }"
        );
    }

    proptest! {
        #[test]
        #[cfg_attr(miri, ignore = "proptest is slow under Miri")]
        fn chunks_tile_the_data_within_the_size_bounds(seed in 1u8.., data in vec(any::<u8>(), 0..6_000)) {
            let gear = table(seed);
            let params = ChunkParams::SCALED;
            let ranges: Vec<Range<usize>> =
                Chunks::with_params(&gear, ObjectClass::Ordinary, &data, params).collect();
            let mut next = 0;
            for (i, range) in ranges.iter().enumerate() {
                prop_assert_eq!(range.start, next);
                next = range.end;
                prop_assert!(range.len() <= params.max);
                if i + 1 < ranges.len() {
                    prop_assert!(range.len() >= params.min, "a short chunk before the last");
                } else {
                    prop_assert!(!range.is_empty());
                }
            }
            prop_assert_eq!(next, data.len(), "the chunks rebuild the data");
            if data.len() <= params.min {
                prop_assert_eq!(ranges.len(), usize::from(!data.is_empty()));
            }
        }

        #[test]
        #[cfg_attr(miri, ignore = "proptest is slow under Miri")]
        fn secret_chunks_are_fixed_steps_of_the_maximum(
            seed in 1u8..,
            data in vec(any::<u8>(), 0..6_000),
        ) {
            let gear = table(seed);
            let params = ChunkParams::SCALED;
            let ranges: Vec<Range<usize>> =
                Chunks::with_params(&gear, ObjectClass::Secret, &data, params).collect();
            let expected: Vec<Range<usize>> = (0..data.len())
                .step_by(params.max)
                .map(|start| start..data.len().min(start + params.max))
                .collect();
            prop_assert_eq!(ranges, expected);
        }
    }
}
