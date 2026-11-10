//! An object's class and whether it has no chunk, one, or more, as the chunker found.

use crate::blob::ObjectClass;

/// The class an object was cut for and whether it has no chunk, a single chunk, or two or more,
/// which together decide whether its blob IDs are keyed (FS-55).
///
/// Only the chunker makes one, from the class it cut for and what it cut:
/// [`ChunkRef::object_shape`] and [`Chunks::object_shape`]. A shape alone does not say which
/// object it describes, so an [`ObjectSealer`](crate::blob::ObjectSealer) built from it checks
/// every [`ChunkRef`] it seals against it, and its
/// [`finish`](crate::blob::ObjectSealer::finish) fails unless the object's last chunk was
/// sealed. A writer therefore cannot give keyed blob IDs to an object of a single chunk, which a
/// reader, deriving the kind from the manifest's `chunk_count`, would never notice (T-85), nor
/// seal as ordinary an object it cut as secret, or the reverse.
///
/// [`ChunkRef`]: crate::chunk::ChunkRef
/// [`ChunkRef::object_shape`]: crate::chunk::ChunkRef::object_shape
/// [`Chunks::object_shape`]: crate::chunk::Chunks::object_shape
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ObjectShape {
    class: ObjectClass,
    count: ChunkCount,
}

/// How many chunks an object has, as far as its blob IDs care.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum ChunkCount {
    /// Empty data: nothing to seal.
    Zero,
    /// One chunk.
    One,
    /// Two or more chunks.
    Many,
}

impl ObjectShape {
    /// The shape of an object of `class` with `count` chunks.
    pub(crate) const fn new(class: ObjectClass, count: ChunkCount) -> Self {
        Self { class, count }
    }

    /// The class the object was cut for, which its sealer uses too.
    #[must_use]
    pub const fn class(self) -> ObjectClass {
        self.class
    }

    /// Whether the object has no chunk: its data is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        matches!(self.count, ChunkCount::Zero)
    }

    /// Whether the object has exactly one chunk.
    #[must_use]
    pub const fn is_single(self) -> bool {
        matches!(self.count, ChunkCount::One)
    }

    /// The number of chunks [`BlobIdKind::for_object`](crate::blob::BlobIdKind::for_object)
    /// needs: 0, 1, or 2 for any number from two.
    pub(crate) const fn kind_count(self) -> u64 {
        match self.count {
            ChunkCount::Zero => 0,
            ChunkCount::One => 1,
            ChunkCount::Many => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_count_answers_one_question() {
        let cases = [
            (ChunkCount::Zero, true, false, 0),
            (ChunkCount::One, false, true, 1),
            (ChunkCount::Many, false, false, 2),
        ];
        for (count, empty, single, kind_count) in cases {
            let shape = ObjectShape::new(ObjectClass::Secret, count);
            assert_eq!(
                (shape.is_empty(), shape.is_single(), shape.kind_count()),
                (empty, single, kind_count),
                "{count:?}"
            );
            assert_eq!(shape.class(), ObjectClass::Secret);
        }
    }
}
