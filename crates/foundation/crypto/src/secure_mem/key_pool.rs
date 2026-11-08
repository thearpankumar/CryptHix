//! The arenas of key slots and the fallback from one level to the next.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::secure_mem::arena::Arena;
use crate::secure_mem::fork_generation::{self, Generation};
use crate::secure_mem::lock_budget::Budget;
use crate::secure_mem::region::{Refusal, Region};
use crate::secure_mem::{Config, Fallback, KeySlot, Level, MemError, Status};

/// Levels a key arena is tried at, strongest first.
const TIERS: [Level; 4] = [
    Level::Secret,
    Level::Locked,
    Level::DumpExcluded,
    Level::Heap,
];

/// Key slots in arenas of protected memory, grown one arena at a time up to the configured
/// number of pages.
///
/// Arenas are never unmapped, even once all their keys are dropped, so a `memfd_secret` arena
/// keeps the kernel from hibernating until the process exits. Dropping keys before hibernation
/// (M-11) will need a way to release them.
pub(crate) struct KeyPool {
    config: Config,
    generation: Generation,
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    arenas: Vec<Arc<Arena>>,
    pages: usize,
    reason: Option<Fallback>,
    last_failure: Option<MemError>,
}

impl KeyPool {
    /// An empty pool; nothing is mapped until the first key or [`reserve`](KeyPool::reserve).
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config,
            generation: fork_generation::current(),
            state: Mutex::new(PoolState::default()),
        }
    }

    /// Whether this process made the pool, in its fork generation. A child forked from it
    /// inherits the pool but none of its mapped arenas (`MADV_DONTFORK`), and its lock may have
    /// been held by another thread at the fork, so the child must not use it.
    pub(crate) fn in_this_process(&self) -> bool {
        self.generation == fork_generation::current()
    }

    /// The most bytes of `RLIMIT_MEMLOCK` this pool can charge, kept for its keys.
    #[cfg(all(target_os = "linux", not(miri)))]
    pub(crate) fn lock_reserve(&self) -> usize {
        self.config.lock_reserve()
    }

    /// Maps the first arena now, so a level below the minimum shows at startup.
    ///
    /// # Errors
    ///
    /// As [`slot`](KeyPool::slot), when no arena exists yet and none can be mapped. The error is
    /// also kept for [`status`](KeyPool::status), and the pool stays usable: a later call tries
    /// again, with the same minimum.
    pub(crate) fn reserve(&self) -> Result<(), MemError> {
        let mut state = self.state();
        if state.arenas.is_empty() {
            self.grow(&mut state)?;
        }
        Ok(())
    }

    /// A free slot of 32 zero bytes, from an existing arena or a new one.
    ///
    /// # Errors
    ///
    /// When every slot is taken and no new arena can be added: [`MemError::PoolExhausted`] at
    /// the page cap, [`MemError::BelowMinimum`] if the best level available is below the
    /// minimum, [`MemError::MapFailed`] if every level was refused, or [`MemError::TooLarge`] if
    /// the configured arena size passes the address space.
    pub(crate) fn slot(&self) -> Result<KeySlot, MemError> {
        let mut state = self.state();
        if let Some(slot) = state.arenas.iter().rev().find_map(Arena::take) {
            return Ok(slot);
        }
        let arena = self.grow(&mut state)?;
        Arena::take(&arena).ok_or(MemError::PoolExhausted)
    }

    /// The report for [`status`](fn@crate::secure_mem::status). `buffer_level` and
    /// `buffer_reason` are filled in by the caller.
    pub(crate) fn status(&self) -> Status {
        let state = self.state();
        Status {
            initialised: true,
            key_level: state.arenas.iter().map(|arena| arena.level()).min(),
            buffer_level: None,
            buffer_reason: None,
            minimum: self.config.minimum(),
            key_slots_used: state.arenas.iter().map(|arena| arena.used()).sum(),
            key_slots_total: state.arenas.iter().map(|arena| arena.slots()).sum(),
            reason: state.reason,
            last_failure: state.last_failure,
        }
    }

    /// Maps one more arena at the strongest level available, never below the minimum, and keeps
    /// the error if it cannot.
    fn grow(&self, state: &mut PoolState) -> Result<Arc<Arena>, MemError> {
        self.try_grow(state)
            .inspect_err(|error| state.last_failure = Some(*error))
    }

    fn try_grow(&self, state: &mut PoolState) -> Result<Arc<Arena>, MemError> {
        let pages = self.config.pages_per_arena();
        let total = state
            .pages
            .checked_add(pages.get())
            .filter(|total| *total <= self.config.max_pages())
            .ok_or(MemError::PoolExhausted)?;
        let region = self.map(pages, &mut state.reason)?;
        let arena = Arc::new(Arena::new(region));
        state.arenas.push(Arc::clone(&arena));
        state.pages = total;
        Ok(arena)
    }

    /// Tries each level from the strongest allowed down. A region below the minimum is unmapped
    /// again and reported in the error, as is a build with no protected memory when the minimum
    /// is above [`Level::Heap`]. Whenever a region falls below the strongest level, kept
    /// or not, or every level is refused, `reason` becomes the cause (see [`Fallback::cause`]).
    /// An arena too large for the address space is refused before any level is tried, with no
    /// reason: no level would help.
    fn map(&self, pages: NonZeroUsize, reason: &mut Option<Fallback>) -> Result<Region, MemError> {
        if !Region::fits(pages) {
            return Err(MemError::TooLarge);
        }
        let want = self.config.minimum();
        let strongest = self.config.strongest();
        if strongest < want {
            return Err(MemError::BelowMinimum {
                got: strongest,
                want,
            });
        }
        let mut last_refusal: Option<Refusal> = None;
        // The heap is a key tier only where the app allows it outright.
        let tiers = TIERS
            .into_iter()
            .filter(|level| *level <= strongest && (*level > Level::Heap || want == Level::Heap));
        for level in tiers {
            match Region::new(level, pages, Budget::Keys) {
                Ok(region) => {
                    if let Some(cause) = Fallback::cause(level, region.level(), last_refusal) {
                        *reason = Some(cause);
                    }
                    if region.level() < want {
                        return Err(MemError::BelowMinimum {
                            got: region.level(),
                            want,
                        });
                    }
                    return Ok(region);
                }
                Err(refusal) => last_refusal = Some(refusal),
            }
        }
        if let Some(refusal) = last_refusal {
            *reason = Some(refusal.fallback());
        }
        // A build without protected memory refuses every mapped level, so the heap the minimum
        // skipped is the best there is.
        if matches!(last_refusal, Some(Refusal::Platform)) && want > Level::Heap {
            return Err(MemError::BelowMinimum {
                got: Level::Heap,
                want,
            });
        }
        Err(MemError::MapFailed)
    }

    /// The state, locked.
    ///
    /// Poison is treated as a bug, as the style guide says, rather than recovered from, because
    /// nothing that runs while the lock is held can panic. `slot`, `reserve` and `status` only
    /// take a free slot from the lock-free bitmap, map and wrap a region (`Region::new` and its
    /// Linux helpers report every failure as a `Refusal`; `as_ptr`'s fork check cannot fire on a
    /// region this process has just made), drop a region below the minimum, and push to or sum
    /// over `arenas`, whose counts are bounded by the address space. Running out of memory in
    /// `Vec::push`, `Arc::new` or the bitmap's allocation aborts the process instead of
    /// panicking, and the one assertion reachable here, `munmap` of a whole owned mapping
    /// failing in a debug build, cannot happen. So a poisoned lock would mean an invariant here
    /// is already broken, and handing out more keys from that state would be worse than
    /// stopping. Dropping a key never takes this lock (it frees its slot in the arena bitmap),
    /// so it neither waits here nor panics on poison.
    fn state(&self) -> MutexGuard<'_, PoolState> {
        self.state
            .lock()
            .expect("nothing panics while the key pool's lock is held")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_mem::arena::SLOT_LEN;

    fn heap_pool(per_arena: usize, max: usize) -> KeyPool {
        KeyPool::new(
            Config::default()
                .with_strongest(Level::Heap)
                .with_minimum(Level::Heap)
                .with_pages_per_arena(per_arena)
                .with_max_pages(max),
        )
    }

    fn slots_per_page() -> usize {
        Region::page_size() / SLOT_LEN
    }

    #[test]
    fn grows_by_arenas_up_to_the_cap() {
        let pool = heap_pool(1, 2);
        let slots: Vec<_> = (0..2 * slots_per_page())
            .map(|_| pool.slot().expect("within the cap"))
            .collect();
        assert_eq!(pool.status().last_failure, None);
        assert_eq!(pool.slot().err(), Some(MemError::PoolExhausted));
        let status = pool.status();
        assert_eq!(status.key_slots_used, slots.len());
        assert_eq!(status.key_slots_total, slots.len());
        assert_eq!(
            status.key_level,
            Some(Level::Heap),
            "the arenas that exist are unchanged by the failure"
        );
        assert_eq!(status.last_failure, Some(MemError::PoolExhausted));
        assert_eq!(status.reason, None, "the strongest level was reached");
        drop(slots);
        assert_eq!(pool.status().key_slots_used, 0);
        pool.slot().expect("freed slots are reused");
    }

    /// Each slot keeps its arena alive: once the pool is gone, slots in its first and second
    /// arena still read, write and wipe their own bytes, on this thread and on others. Under
    /// Miri a freed arena would be a use after free.
    #[test]
    fn slots_outlive_their_pool() {
        /// The bytes slot `index` is filled with.
        fn tag(index: usize) -> u8 {
            u8::try_from(index % 255 + 1).expect("1 to 255")
        }

        let pool = KeyPool::new(Config::default().with_pages_per_arena(1).with_max_pages(2));
        let mut slots: Vec<KeySlot> = (0..=slots_per_page())
            .map(|_| pool.slot().expect("within the cap"))
            .collect();
        assert_eq!(
            pool.status().key_slots_total,
            2 * slots_per_page(),
            "two arenas"
        );
        for (index, slot) in slots.iter_mut().enumerate() {
            slot.bytes_mut().fill(tag(index));
        }
        drop(pool);
        let last = slots.pop().expect("a slot in the second arena");
        std::thread::scope(|scope| {
            scope.spawn(move || {
                assert_eq!(last.bytes(), &[tag(slots_per_page()); SLOT_LEN]);
                drop(last);
            });
        });
        for (index, slot) in slots.iter_mut().enumerate() {
            assert_eq!(slot.bytes(), &[tag(index); SLOT_LEN]);
            slot.bytes_mut().fill(!tag(index));
        }
        drop(slots);
    }

    /// `reason` says why some arena fell back, so a later arena that reaches the strongest level
    /// leaves it. The first arena's fallback is set in the state, since this process's levels
    /// cannot be chosen; the second arena is mapped by the pool as usual.
    #[test]
    fn a_later_arena_at_the_strongest_level_keeps_the_reason() {
        let pool = heap_pool(1, 2);
        let first: Vec<_> = (0..slots_per_page())
            .map(|_| pool.slot().expect("within the cap"))
            .collect();
        assert_eq!(
            pool.status().reason,
            None,
            "the strongest level was reached"
        );
        pool.state().reason = Some(Fallback::LockLimit);
        let second = pool.slot().expect("a second arena");
        let status = pool.status();
        assert_eq!(status.key_slots_total, 2 * slots_per_page(), "two arenas");
        assert_eq!(status.key_level, Some(Level::Heap));
        assert_eq!(status.reason, Some(Fallback::LockLimit));
        drop((first, second));
    }

    #[test]
    fn reserve_maps_one_arena_once() {
        let pool = heap_pool(1, 4);
        pool.reserve().expect("the heap is always available");
        pool.reserve().expect("a second reserve is a no-op");
        assert_eq!(pool.status().key_slots_total, slots_per_page());
    }

    #[test]
    fn an_unreachable_minimum_is_an_error_naming_the_level_got() {
        let pool = KeyPool::new(
            Config::default()
                .with_strongest(Level::Heap)
                .with_minimum(Level::Locked),
        );
        let below = MemError::BelowMinimum {
            got: Level::Heap,
            want: Level::Locked,
        };
        assert_eq!(pool.reserve().err(), Some(below));
        assert_eq!(
            pool.slot().err(),
            Some(below),
            "a failed reserve leaves the minimum in force"
        );
        let status = pool.status();
        assert_eq!(status.last_failure, Some(below));
        assert_eq!(status.key_level, None, "no arena was kept");
        assert_eq!(status.minimum, Level::Locked);
        let pool = KeyPool::new(
            Config::default()
                .with_strongest(Level::DumpExcluded)
                .with_minimum(Level::Locked),
        );
        assert!(
            pool.slot().is_err(),
            "a level above `strongest` is never reached"
        );
    }

    proptest::proptest! {
        /// Any sequence of takes and frees: a new slot is all zero, and no slot ever shares
        /// bytes with another (each keeps the tag written into it).
        #[test]
        fn slots_never_alias_and_start_zeroed(ops in proptest::collection::vec(
            (proptest::bool::ANY, proptest::num::usize::ANY),
            1..300,
        )) {
            let pool = heap_pool(1, 2);
            let mut live: Vec<(KeySlot, u8)> = Vec::new();
            let mut next_tag = 1u8;
            for (take, pick) in ops {
                if take || live.is_empty() {
                    let Ok(mut slot) = pool.slot() else {
                        proptest::prop_assert_eq!(live.len(), 2 * slots_per_page());
                        continue;
                    };
                    proptest::prop_assert_eq!(slot.bytes(), &[0; SLOT_LEN]);
                    slot.bytes_mut().fill(next_tag);
                    live.push((slot, next_tag));
                    next_tag = next_tag.wrapping_add(1).max(1);
                } else {
                    drop(live.swap_remove(pick % live.len()));
                }
                for (slot, tag) in &live {
                    proptest::prop_assert_eq!(slot.bytes(), &[*tag; SLOT_LEN]);
                }
            }
        }
    }

    #[test]
    fn absurd_arena_sizes_fail_cleanly() {
        for config in [
            Config::default()
                .with_pages_per_arena(usize::MAX)
                .with_max_pages(usize::MAX),
            Config::default()
                .with_strongest(Level::Heap)
                .with_minimum(Level::Heap)
                .with_pages_per_arena(usize::MAX / 2)
                .with_max_pages(usize::MAX),
        ] {
            let pool = KeyPool::new(config);
            assert_eq!(pool.slot().err(), Some(MemError::TooLarge), "{config:?}");
            let status = pool.status();
            assert_eq!(status.key_slots_total, 0, "nothing was mapped");
            assert_eq!(status.last_failure, Some(MemError::TooLarge));
            assert_eq!(status.reason, None, "no level was tried: {config:?}");
        }
    }

    #[cfg(not(all(target_os = "linux", not(miri))))]
    #[test]
    fn without_protected_memory_keys_get_the_heap_and_say_why() {
        let pool = KeyPool::new(Config::default());
        let slot = pool.slot().expect("the heap is always available");
        assert_eq!(slot.level(), Level::Heap);
        let status = pool.status();
        assert_eq!(status.key_level, Some(Level::Heap));
        assert_eq!(status.reason, Some(Fallback::Platform));
        assert_eq!(status.last_failure, None);
    }

    #[cfg(not(all(target_os = "linux", not(miri))))]
    #[test]
    fn without_protected_memory_a_minimum_above_the_heap_is_below_minimum() {
        for want in [Level::DumpExcluded, Level::Locked, Level::Secret] {
            let pool = KeyPool::new(Config::default().with_minimum(want));
            let below = MemError::BelowMinimum {
                got: Level::Heap,
                want,
            };
            assert_eq!(pool.reserve().err(), Some(below), "{want}");
            assert_eq!(pool.slot().err(), Some(below), "{want}");
            let status = pool.status();
            assert_eq!(status.key_level, None, "{want}: no arena was kept");
            assert_eq!(status.reason, Some(Fallback::Platform), "{want}");
            assert_eq!(status.last_failure, Some(below), "{want}");
        }
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn linux_gives_at_least_the_floor() {
        let pool = KeyPool::new(Config::default());
        let slot = pool.slot().expect("anonymous mappings always work");
        assert!(slot.level() >= Level::DumpExcluded);
        assert_eq!(pool.status().key_level, Some(slot.level()));
    }

    /// Set, in a process [`probe_in_a_child`] starts, to where that process reads.
    #[cfg(all(target_os = "linux", not(miri)))]
    const PROBE: &str = "CRYPTHIX_TEST_ARENA_PROBE";

    /// A pool's first one-page arena, at whatever mapped level this system gives keys, has a
    /// guard page on each side: reading its last data byte works, while reading the byte before
    /// its first slot or the byte after its last kills the reader with `SIGSEGV`. Each read runs
    /// in a process of its own, this test binary started again for this test alone, so the
    /// faults end only those processes.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn reading_past_either_end_of_a_key_arena_faults() {
        if let Some(at) = std::env::var_os(PROBE) {
            read_around_the_first_arena(&at.to_string_lossy());
            return;
        }
        assert_eq!(probe_in_a_child("last"), None, "the probe itself works");
        assert_eq!(
            probe_in_a_child("below"),
            Some(libc::SIGSEGV),
            "the guard below"
        );
        assert_eq!(
            probe_in_a_child("above"),
            Some(libc::SIGSEGV),
            "the guard above"
        );
    }

    /// Runs [`reading_past_either_end_of_a_key_arena_faults`] again in a new process that reads
    /// `at`, and returns the signal that killed it, or `None` if its read worked and it passed.
    ///
    /// A new process rather than `fork`: the child maps an arena, which allocates, and a child
    /// forked from this multithreaded test harness may only make async-signal-safe calls.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn probe_in_a_child(at: &str) -> Option<i32> {
        use std::os::unix::process::ExitStatusExt;

        // Test names are module paths without the crate's name.
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, path)| path);
        let name = format!("{module}::reading_past_either_end_of_a_key_arena_faults");
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([name.as_str(), "--exact", "--nocapture"])
            .env(PROBE, at)
            .output()
            .expect("the test binary runs");
        let signal = output.status.signal();
        if signal.is_none() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("test result: ok. 1 passed;"),
                "the {at} probe failed: {:?}\n{stdout}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        signal
    }

    /// In a process of its own: maps a pool's first arena and reads the byte `at` names, `last`
    /// (its last data byte), `below` (the byte before slot 0) or `above` (the byte after the last
    /// slot).
    #[cfg(all(target_os = "linux", not(miri)))]
    fn read_around_the_first_arena(at: &str) {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .expect("a process may always make itself not dumpable");
        let pool = KeyPool::new(Config::default().with_pages_per_arena(1));
        let slot = pool.slot().expect("anonymous mappings always work");
        assert_eq!(slot.index(), 0, "the first slot of the first arena");
        assert!(slot.level() >= Level::DumpExcluded, "a mapped arena");
        let arena = Arc::clone(&pool.state().arenas[0]);
        let start = arena.slot_ptr(0).cast::<u8>();
        let address = match at {
            "last" => start.wrapping_add(Region::page_size() - 1),
            "below" => start.wrapping_sub(1),
            "above" => start.wrapping_add(Region::page_size()),
            other => panic!("no probe named {other}"),
        };
        #[expect(
            unsafe_code,
            reason = "reads at a guard page on purpose, to show it faults"
        )]
        // SAFETY: `last` reads a data byte of the arena, which this process mapped, zeroed and
        // still holds through `arena`, and no reference to which exists (the one slot taken is
        // slot 0, at the other end of the page). `below` and `above` are a deliberate fault: the
        // guard page has no access, so the CPU traps before any byte is read and the kernel ends
        // this process with `SIGSEGV`, which the parent test checks. The process runs only this
        // test and writes no core dump, so that signal is the fault's only effect.
        let byte = unsafe { address.read_volatile() };
        assert_eq!(byte, 0, "an untaken slot is zero");
    }
}
