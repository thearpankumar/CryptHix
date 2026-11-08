//! One 32-byte slot of protected memory, owned by one key.
#![expect(
    unsafe_code,
    reason = "a slot hands out references into memory it owns but cannot borrow from"
)]

use std::fmt;
use std::sync::Arc;

use zeroize::Zeroize;

use crate::secure_mem::Level;
use crate::secure_mem::arena::{Arena, SLOT_LEN};

/// 32 bytes of protected memory holding one key, wiped and returned to its arena on drop.
///
/// It has no `Clone`, so its bytes have exactly one owner. A slot belongs to the process that
/// took it: in a forked child [`bytes`](KeySlot::bytes) panics, and dropping it wipes the
/// child's copy of a [`Level::Heap`] slot but leaves a mapped one, which the child does not
/// have, alone.
pub(crate) struct KeySlot {
    arena: Arc<Arena>,
    index: usize,
}

impl KeySlot {
    /// Wraps slot `index` of `arena`, which the caller has just marked used.
    pub(crate) const fn new(arena: Arc<Arena>, index: usize) -> Self {
        Self { arena, index }
    }

    /// The key bytes.
    ///
    /// # Panics
    ///
    /// In a child forked after the slot was taken, where its memory is not mapped.
    pub(crate) fn bytes(&self) -> &[u8; SLOT_LEN] {
        // SAFETY: the arena's bitmap gave `index` to this slot alone, the arena (and so its
        // mapping) lives as long as `self.arena`, the slot is aligned for a byte array, and it
        // was zeroed when mapped or wiped when last freed, so it is initialised. Writes need
        // `&mut self`, so no mutable reference exists while this one does.
        unsafe { &*self.arena.slot_ptr(self.index) }
    }

    /// The key bytes, to fill in place.
    ///
    /// # Panics
    ///
    /// As [`bytes`](KeySlot::bytes).
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN] {
        // SAFETY: as in `bytes`; `&mut self` makes this the only reference to the slot.
        unsafe { &mut *self.arena.slot_ptr(self.index) }
    }

    /// The protection of the slot.
    pub(crate) fn level(&self) -> Level {
        self.arena.level()
    }

    /// The slot's index in its arena, for tests.
    #[cfg(test)]
    pub(crate) const fn index(&self) -> usize {
        self.index
    }
}

impl Drop for KeySlot {
    fn drop(&mut self) {
        // `None` only for a mapping inherited across `fork`, whose page stayed with the parent,
        // which wipes it.
        if let Some(slot) = self.arena.wipeable_slot(self.index) {
            // SAFETY: the arena's bitmap gave `index` to this slot alone, the arena lives as long
            // as `self.arena`, and `wipeable_slot` returned it, so its bytes are this process's
            // memory. `&mut self` makes this the only reference.
            unsafe { &mut *slot }.zeroize();
        }
        // The bitmap is this process's own heap memory, in a forked child its copy.
        self.arena.free(self.index);
    }
}

impl fmt::Debug for KeySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySlot")
            .field("level", &self.level())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crate::secure_mem::lock_budget::Budget;
    use crate::secure_mem::region::Region;

    /// A heap arena's bytes in a forked child are the child's own copy, so a slot the child
    /// inherited is wiped when the child drops it, though it may not be read.
    #[test]
    fn a_forked_child_wipes_its_copy_of_a_heap_slot() {
        let mut region = Region::new(Level::Heap, NonZeroUsize::MIN, Budget::Keys)
            .expect("the heap is always available");
        region.pretend_inherited();
        let arena = Arc::new(Arena::new(region));
        let slot = Arena::take(&arena).expect("a free slot");
        let bytes = arena
            .wipeable_slot(slot.index())
            .expect("a heap copy is the child's own memory");
        // SAFETY: the slot's 32 bytes, in the arena kept alive by `arena`; no reference into
        // them exists.
        unsafe { bytes.write([0x5a; SLOT_LEN]) };
        drop(slot);
        // SAFETY: as above.
        assert_eq!(unsafe { bytes.read() }, [0; SLOT_LEN], "wiped on drop");
        assert_eq!(arena.used(), 0, "and freed");
    }

    /// The crate-private part of `tests/redaction.rs`: `Debug` names the slot and its level but
    /// shows no key byte, in decimal or hex, and no address.
    #[test]
    fn debug_shows_no_key_bytes_or_address() {
        let mut slot = crate::secure_mem::take_key_slot().expect("a free slot");
        slot.bytes_mut().fill(0xab);
        for debug in [format!("{slot:?}"), format!("{slot:#x?}")] {
            assert!(debug.contains("KeySlot"), "{debug}");
            for leak in ["171", "ab, ab", "abab"] {
                assert!(!debug.contains(leak), "{debug} shows {leak:?}");
            }
        }
        assert!(
            !format!("{slot:?}").contains("0x"),
            "{slot:?} shows an address"
        );
    }
}
