//! Cutting data already in memory.

use std::fmt;
use std::iter::{self, FusedIterator};
use std::ops::Range;

use crate::blob::ObjectClass;
use crate::chunk::cut;
use crate::chunk::{ChunkCount, ChunkParams, ChunkRef, GearTable, ObjectShape};

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
    /// Index of the next chunk.
    index: u64,
    params: ChunkParams,
}

impl<'a> Chunks<'a> {
    /// The chunks of `data` in an object of `class`; `gear` is used for the ordinary class
    /// only.
    pub fn new(gear: &'a GearTable, class: ObjectClass, data: &'a [u8]) -> Self {
        Self::with_params(gear, class, data, ChunkParams::FORMAT_0)
    }

    /// The chunks of `data` cut at the scaled-down sizes 64, 256 and 1,024 bytes, with the
    /// level 2 masks for a 256-byte average, for the fuzz targets only: not a format 0 cut. It
    /// lets the `chunker` fuzz target reach every cut-point edge with inputs of a few KiB,
    /// where the format 0 hash is only tested 64 KiB into a chunk.
    #[cfg(feature = "vectors")]
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
            index: 0,
            params,
        }
    }

    /// The class the chunks are cut for and whether `data` is no chunk, one, or more, which a
    /// writer passes to [`ObjectSealer::new`](crate::blob::ObjectSealer::new) (FS-55). It
    /// depends on the whole data, not on how far the iterator has gone, and costs one cut.
    #[must_use]
    pub fn object_shape(&self) -> ObjectShape {
        let first = cut::cut_for(self.class, self.gear, self.data, &self.params);
        let count = if self.data.is_empty() {
            ChunkCount::Zero
        } else if first >= self.data.len() {
            ChunkCount::One
        } else {
            ChunkCount::Many
        };
        ObjectShape::new(self.class, count)
    }

    /// The chunks not yet cut, as the [`ChunkRef`]s an
    /// [`ObjectSealer`](crate::blob::ObjectSealer) seals: each with its bytes, its index in the
    /// object and whether it is the last.
    pub fn chunk_refs(self) -> impl Iterator<Item = ChunkRef<'a>> {
        let mut chunks = self;
        iter::from_fn(move || {
            let index = chunks.index;
            let range = chunks.next()?;
            let is_last = range.end == chunks.data.len();
            let bytes = chunks.data.get(range)?;
            Some(ChunkRef::new(bytes, index, is_last, chunks.class))
        })
    }
}

impl Iterator for Chunks<'_> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Range<usize>> {
        let rest = self.data.get(self.offset..)?;
        let len = cut::cut_for(self.class, self.gear, rest, &self.params);
        if len == 0 {
            return None;
        }
        let start = self.offset;
        self.offset += len;
        self.index = self.index.saturating_add(1);
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
    use proptest::prelude::{prop_assert, prop_assert_eq, proptest};

    use super::*;
    use crate::test_data::gear_table as table;
    use crate::test_data::{any_byte, bytes, chunk_ranges, pseudo_random};

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
    fn the_shape_counts_none_one_or_more_chunks() {
        let gear = table(1);
        let params = ChunkParams::SCALED;
        for class in CLASSES {
            for len in [0, 1, params.min, params.max, params.max + 1, 6_000] {
                let data = pseudo_random(3, len);
                let count = chunk_ranges(&gear, class, &data, params).len();
                let shape = Chunks::with_params(&gear, class, &data, params).object_shape();
                assert_eq!(
                    (shape.is_empty(), shape.is_single()),
                    (count == 0, count == 1),
                    "{class:?} {len}"
                );
                assert_eq!(shape.class(), class);
            }
        }
    }

    #[test]
    fn chunk_refs_are_the_ranges_with_their_index_and_last_flag() {
        let gear = table(1);
        let params = ChunkParams::SCALED;
        for class in CLASSES {
            let data = pseudo_random(4, 5_000);
            let ranges = chunk_ranges(&gear, class, &data, params);
            assert!(ranges.len() > 2, "{class:?}: enough chunks to test");
            let mut chunks = Chunks::with_params(&gear, class, &data, params);
            assert_eq!(chunks.next(), Some(ranges[0].clone()));
            let shape = chunks.object_shape();
            let refs: Vec<ChunkRef<'_>> = chunks.chunk_refs().collect();
            assert_eq!(refs.len(), ranges.len() - 1, "{class:?}: the rest");
            for (chunk, range) in refs.iter().zip(&ranges[1..]) {
                let index = chunk.index();
                assert_eq!(chunk.bytes(), &data[range.clone()], "{class:?} {index}");
                assert_eq!(
                    index,
                    ranges.iter().position(|r| r == range).expect("a range") as u64
                );
                assert_eq!(
                    chunk.is_last(),
                    range.end == data.len(),
                    "{class:?} {index}"
                );
                assert_eq!(chunk.object_shape(), shape, "{class:?} {index}");
            }
            let one: Vec<ChunkRef<'_>> = Chunks::with_params(&gear, class, &data[..10], params)
                .chunk_refs()
                .collect();
            assert_eq!(one.len(), 1);
            assert_eq!((one[0].index(), one[0].is_last()), (0, true));
            let none = Chunks::with_params(&gear, class, &[], params).chunk_refs();
            assert_eq!(none.count(), 0);
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
        fn chunks_tile_the_data_within_the_size_bounds(seed in 1u8.., data in bytes(0..6_000, any_byte)) {
            let gear = table(seed);
            let params = ChunkParams::SCALED;
            let ranges = chunk_ranges(&gear, ObjectClass::Ordinary, &data, params);
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
        fn secret_chunks_are_fixed_steps_of_the_maximum(
            seed in 1u8..,
            data in bytes(0..6_000, any_byte),
        ) {
            let gear = table(seed);
            let params = ChunkParams::SCALED;
            let ranges = chunk_ranges(&gear, ObjectClass::Secret, &data, params);
            let expected: Vec<Range<usize>> = (0..data.len())
                .step_by(params.max)
                .map(|start| start..data.len().min(start + params.max))
                .collect();
            prop_assert_eq!(ranges, expected);
        }
    }
}
