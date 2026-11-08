//! A region of secret memory cut into 32-byte key slots.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::secure_mem::KeySlot;
use crate::secure_mem::Level;
use crate::secure_mem::region::Region;

/// Bytes in one key slot.
pub(crate) const SLOT_LEN: usize = 32;

/// One mapping of key slots and the bitmap of those in use.
///
/// The bitmap is lock-free: a slot is claimed by the one `fetch_or` that sets its bit and
/// freed by a `fetch_and`, so dropping a key never waits on a lock and no panic can leave the
/// bitmap half-written. Freeing releases the wiped slot and claiming acquires it, so its next
/// holder sees the zeros.
pub(crate) struct Arena {
    region: Region,
    used: Box<[AtomicU64]>,
}

impl Arena {
    /// Cuts `region` into slots, all free.
    pub(crate) fn new(region: Region) -> Self {
        let slots = region.len() / SLOT_LEN;
        Self {
            region,
            used: (0..slots.div_ceil(64)).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// The protection of every slot in the arena.
    pub(crate) const fn level(&self) -> Level {
        self.region.level()
    }

    /// Slots in the arena.
    pub(crate) const fn slots(&self) -> usize {
        self.region.len() / SLOT_LEN
    }

    /// Slots in use.
    pub(crate) fn used(&self) -> usize {
        self.used
            .iter()
            .map(|word| word.load(Ordering::Acquire).count_ones() as usize)
            .sum()
    }

    /// Takes a free slot, which holds 32 zero bytes, or `None` if all are in use.
    pub(crate) fn take(arena: &Arc<Self>) -> Option<KeySlot> {
        let index = arena.claim()?;
        Some(KeySlot::new(Arc::clone(arena), index))
    }

    /// Sets the bit of the lowest free slot and returns its index. A bit another thread set
    /// first is skipped: `fetch_or` returns the word as it was, so exactly one caller sees the
    /// bit clear.
    fn claim(&self) -> Option<usize> {
        let slots = self.slots();
        for (word_index, word) in self.used.iter().enumerate() {
            let mut seen = word.load(Ordering::Acquire);
            while seen != u64::MAX {
                let bit = (!seen).trailing_zeros() as usize;
                let index = word_index * 64 + bit;
                if index >= slots {
                    // The bits past the last slot are never set, and every lower one is taken.
                    break;
                }
                let mask = 1 << bit;
                seen = word.fetch_or(mask, Ordering::AcqRel);
                if seen & mask == 0 {
                    return Some(index);
                }
            }
        }
        None
    }

    /// The first byte of slot `index`. The pointer is only dereferenced by the [`KeySlot`] that
    /// holds `index`.
    pub(crate) fn slot_ptr(&self, index: usize) -> *mut [u8; SLOT_LEN] {
        debug_assert!(index < self.slots(), "slot index out of range");
        self.region
            .as_ptr()
            .wrapping_add(index * SLOT_LEN)
            .cast::<[u8; SLOT_LEN]>()
    }

    /// The first byte of slot `index`, to wipe it, if its bytes are this process's memory (see
    /// [`Region::wipeable_ptr`]).
    pub(crate) fn wipeable_slot(&self, index: usize) -> Option<*mut [u8; SLOT_LEN]> {
        debug_assert!(index < self.slots(), "slot index out of range");
        let data = self.region.wipeable_ptr()?;
        Some(data.wrapping_add(index * SLOT_LEN).cast::<[u8; SLOT_LEN]>())
    }

    /// Marks slot `index` free. Its holder has wiped it.
    pub(crate) fn free(&self, index: usize) {
        let mask = 1 << (index % 64);
        let was = self.used[index / 64].fetch_and(!mask, Ordering::Release);
        debug_assert!(was & mask != 0, "a slot is freed only by its holder");
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crate::secure_mem::lock_budget::Budget;

    fn arena() -> Arc<Arena> {
        Arc::new(Arena::new(
            Region::new(Level::Heap, NonZeroUsize::MIN, Budget::Keys)
                .expect("the heap is always available"),
        ))
    }

    #[test]
    fn every_slot_can_be_taken_once_then_none() {
        let arena = arena();
        let slots: Vec<_> = (0..arena.slots())
            .map(|_| Arena::take(&arena).expect("a free slot"))
            .collect();
        assert_eq!(arena.used(), arena.slots());
        assert!(Arena::take(&arena).is_none());
        let mut indices: Vec<_> = slots.iter().map(KeySlot::index).collect();
        indices.sort_unstable();
        indices.dedup();
        assert_eq!(indices.len(), arena.slots(), "no slot was handed out twice");
    }

    /// Threads take and drop slots at once, past the arena's capacity. A slot claimed twice
    /// shows as an owner flag already set, or as another thread's tag in the bytes; under Miri
    /// it is also a data race on the slot.
    #[test]
    fn concurrent_takes_never_alias_and_every_slot_comes_back() {
        use std::sync::Barrier;
        use std::sync::atomic::AtomicBool;
        use std::thread;

        let (threads, rounds, per_round) = if cfg!(miri) { (3, 4, 50) } else { (8, 500, 32) };
        let arena = arena();
        let owned: Vec<AtomicBool> = (0..arena.slots()).map(|_| AtomicBool::new(false)).collect();
        let start = Barrier::new(threads);
        thread::scope(|scope| {
            for thread in 0..threads {
                let (arena, owned, start) = (&arena, &owned, &start);
                let tag = u8::try_from(thread + 1).expect("few threads");
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..rounds {
                        let mut held = Vec::new();
                        while let Some(mut slot) = Arena::take(arena) {
                            assert!(
                                !owned[slot.index()].swap(true, Ordering::AcqRel),
                                "slot {} handed to two holders",
                                slot.index()
                            );
                            assert_eq!(slot.bytes(), &[0; SLOT_LEN], "a taken slot is zero");
                            slot.bytes_mut().fill(tag);
                            held.push(slot);
                            if held.len() == per_round {
                                break;
                            }
                        }
                        thread::yield_now();
                        for slot in held {
                            assert_eq!(slot.bytes(), &[tag; SLOT_LEN], "no one else wrote here");
                            owned[slot.index()].store(false, Ordering::Release);
                        }
                    }
                });
            }
        });
        assert_eq!(arena.used(), 0, "every slot was freed");
        let all: Vec<_> = (0..arena.slots())
            .map(|_| Arena::take(&arena).expect("a free slot"))
            .collect();
        assert_eq!(all.len(), arena.slots(), "every slot can be taken again");
    }

    #[test]
    fn a_dropped_slot_is_wiped_and_reused() {
        let arena = arena();
        let mut slot = Arena::take(&arena).expect("a free slot");
        let index = slot.index();
        slot.bytes_mut().fill(0x5a);
        drop(slot);
        assert_eq!(arena.used(), 0);
        let again = Arena::take(&arena).expect("a free slot");
        assert_eq!(again.index(), index, "the lowest free slot is reused");
        assert_eq!(again.bytes(), &[0; SLOT_LEN], "a freed slot is wiped");
    }
}
