//! One chunk of a stream.

use std::fmt;

use crate::blob::ObjectClass;
use crate::chunk::{ChunkCount, ObjectShape};

/// A chunk cut by a [`StreamChunker`](crate::chunk::StreamChunker), borrowed from its window, or
/// by [`Chunks::chunk_refs`](crate::chunk::Chunks::chunk_refs), borrowed from the data.
///
/// [`is_last`](ChunkRef::is_last) is known when the chunk is cut, so a writer knows at the first
/// chunk whether the object has a single chunk, which decides its blob IDs (FS-55). Only the
/// chunker makes one, so the [`ObjectSealer`](crate::blob::ObjectSealer) that takes it can trust
/// its index, whether it is the last, and its object's class.
#[derive(Clone, Copy)]
pub struct ChunkRef<'a> {
    bytes: &'a [u8],
    index: u64,
    is_last: bool,
    class: ObjectClass,
}

impl<'a> ChunkRef<'a> {
    pub(crate) const fn new(
        bytes: &'a [u8],
        index: u64,
        is_last: bool,
        class: ObjectClass,
    ) -> Self {
        Self {
            bytes,
            index,
            is_last,
            class,
        }
    }

    /// A chunk with any bytes, index, last flag and class, for the test-vector runners and
    /// fuzz targets only: it bypasses the chunker, so it can claim a shape the bytes do not
    /// have.
    #[cfg(feature = "vectors")]
    #[must_use]
    pub const fn from_parts(
        bytes: &'a [u8],
        index: u64,
        is_last: bool,
        class: ObjectClass,
    ) -> Self {
        Self::new(bytes, index, is_last, class)
    }

    /// The chunk's bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The chunk's position in the object, from 0.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Whether this is the object's last chunk. On chunk 0 it means the object has one chunk.
    #[must_use]
    pub const fn is_last(&self) -> bool {
        self.is_last
    }

    /// The class the object was cut for, and whether it has one chunk or more: one exactly
    /// when this is chunk 0 and also the last. Any chunk of the object gives the same answer,
    /// so a writer learns it at the first chunk and passes it to
    /// [`ObjectSealer::new`](crate::blob::ObjectSealer::new) (FS-55).
    #[must_use]
    pub const fn object_shape(&self) -> ObjectShape {
        let count = if self.index == 0 && self.is_last {
            ChunkCount::One
        } else {
            ChunkCount::Many
        };
        ObjectShape::new(self.class, count)
    }
}

/// Prints the length, never the bytes.
impl fmt::Debug for ChunkRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkRef")
            .field("len", &self.bytes.len())
            .field("index", &self.index)
            .field("is_last", &self.is_last)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_give_back_what_was_cut() {
        let chunk = ChunkRef::new(b"bytes", 3, true, ObjectClass::Secret);
        assert_eq!(
            (chunk.bytes(), chunk.index(), chunk.is_last()),
            (&b"bytes"[..], 3, true)
        );
        assert_eq!(
            format!("{chunk:?}"),
            "ChunkRef { len: 5, index: 3, is_last: true }"
        );
    }

    #[test]
    fn the_shape_is_single_only_for_a_first_chunk_that_is_also_last() {
        for class in [ObjectClass::Ordinary, ObjectClass::Secret] {
            let cases = [
                (0, true, ChunkCount::One),
                (0, false, ChunkCount::Many),
                (1, true, ChunkCount::Many),
            ];
            for (index, is_last, count) in cases {
                let shape = ChunkRef::new(b"x", index, is_last, class).object_shape();
                assert_eq!(shape, ObjectShape::new(class, count), "{index} {is_last}");
            }
        }
    }
}
