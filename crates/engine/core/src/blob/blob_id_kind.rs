//! Keyed or random blob IDs (FS-55, FS-56).

use crate::blob::ObjectClass;

/// How the blob IDs of an object's chunks are made (FS-55).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BlobIdKind {
    /// `MAC(K_blobid, chunk plaintext)`: an unchanged chunk keeps its ID, so the next version of
    /// the object reuses its blob (E1). The reader recomputes it (`Binding`, FS-56).
    Keyed,
    /// 32 random bytes: nothing is reused, so content injected into the object cannot confirm a
    /// guess through the number of new packs (T-85).
    Random,
}

impl BlobIdKind {
    /// Keyed exactly when the object is of the ordinary class and has two or more chunks;
    /// random otherwise. A reader takes the class and the chunk count from the manifest
    /// ([`ObjectOpener`](crate::blob::ObjectOpener)); a writer takes the count from the chunker
    /// ([`ObjectSealer`](crate::blob::ObjectSealer) with an
    /// [`ObjectShape`](crate::chunk::ObjectShape)), so the two always agree.
    #[must_use]
    pub const fn for_object(class: ObjectClass, chunk_count: u64) -> Self {
        match class {
            ObjectClass::Ordinary if chunk_count >= 2 => BlobIdKind::Keyed,
            ObjectClass::Ordinary | ObjectClass::Secret => BlobIdKind::Random,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ordinary_objects_of_two_or_more_chunks_are_keyed() {
        let cases = [
            (ObjectClass::Ordinary, 0, BlobIdKind::Random),
            (ObjectClass::Ordinary, 1, BlobIdKind::Random),
            (ObjectClass::Ordinary, 2, BlobIdKind::Keyed),
            (ObjectClass::Ordinary, u64::MAX, BlobIdKind::Keyed),
            (ObjectClass::Secret, 1, BlobIdKind::Random),
            (ObjectClass::Secret, 2, BlobIdKind::Random),
            (ObjectClass::Secret, u64::MAX, BlobIdKind::Random),
        ];
        for (class, count, kind) in cases {
            assert_eq!(
                BlobIdKind::for_object(class, count),
                kind,
                "{class:?} {count}"
            );
        }
    }
}
