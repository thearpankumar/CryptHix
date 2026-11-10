//! An object's class and whether it has one chunk or more, as the chunker found.

use crate::blob::ObjectClass;

/// The class an object was cut for and whether it has a single chunk or two or more, which
/// together decide whether its blob IDs are keyed (FS-55).
///
/// Only the chunker makes one, from the class it cut for and what it cut:
/// [`ChunkRef::object_shape`] and [`Chunks::object_shape`]. A writer therefore cannot claim two
/// or more chunks for an object that has one, which would give a single-chunk object keyed
/// blob IDs that a reader, deriving the kind from the manifest's `chunk_count`, never notices
/// (T-85); nor seal as ordinary an object it cut as secret, or the reverse, since
/// [`ObjectSealer::new`](crate::blob::ObjectSealer::new) takes the class from here.
///
/// [`ChunkRef::object_shape`]: crate::chunk::ChunkRef::object_shape
/// [`Chunks::object_shape`]: crate::chunk::Chunks::object_shape
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ObjectShape {
    class: ObjectClass,
    single: bool,
}

impl ObjectShape {
    /// The shape of an object of `class`, with one chunk if `single`.
    pub(crate) const fn new(class: ObjectClass, single: bool) -> Self {
        Self { class, single }
    }

    /// The class the object was cut for, which its sealer uses too.
    #[must_use]
    pub const fn class(self) -> ObjectClass {
        self.class
    }

    /// Whether the object has exactly one chunk.
    #[must_use]
    pub const fn is_single(self) -> bool {
        self.single
    }
}
