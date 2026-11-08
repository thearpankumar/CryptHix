//! The handle to one block of secret memory: made at a level, wiped and freed on drop.
#![expect(
    unsafe_code,
    reason = "allocating, wiping and freeing memory has no safe interface"
)]

use std::alloc::{self, Layout};
use std::num::NonZeroUsize;
use std::ptr::NonNull;

use zeroize::Zeroize;

use crate::secure_mem::Level;
use crate::secure_mem::fork_generation::{self, Generation};
use crate::secure_mem::lock_budget::Budget;
use crate::secure_mem::region::Refusal;
#[cfg(all(target_os = "linux", not(miri)))]
use crate::secure_mem::region::mapping;

/// A page-aligned, zero-filled block of memory, wiped before it is freed.
///
/// Mappings, which exist only on Linux, are laid out as `[guard][data pages][guard]`, with both
/// guard pages inaccessible, so a linear overrun faults instead of reaching other memory. A
/// [`Level::Heap`] region, the only kind under Miri and on other systems, is a plain heap
/// allocation: no guard pages, no locking, and nothing keeps it out of core dumps or forks.
///
/// A region belongs to the process that made it (its fork [`Generation`]), and
/// [`as_ptr`](Region::as_ptr) panics in a child forked from that process. A child inherits the
/// handle but not a mapping (`MADV_DONTFORK`), so dropping a mapped region there leaves the
/// address alone, since it is unmapped or, once reused, another owner's memory; a heap region's
/// bytes are the child's own copy-on-write copy, which it wipes and frees.
pub(crate) struct Region {
    pub(super) data: NonNull<u8>,
    pub(super) len: usize,
    pub(super) level: Level,
    pub(super) generation: Generation,
    pub(super) backing: Backing,
}

/// What holds a region's memory, and so how it is freed.
pub(super) enum Backing {
    #[cfg(all(target_os = "linux", not(miri)))]
    Mapped {
        base: NonNull<u8>,
        total: usize,
        charged: usize,
        budget: Budget,
    },
    Heap(Layout),
}

// SAFETY: a `Region` owns its memory exclusively and exposes it only as a raw pointer. Callers
// that build references from it keep them disjoint (see `Arena` and `SecretVec`), so moving or
// sharing the handle between threads is sound.
unsafe impl Send for Region {}
// SAFETY: as above; `&Region` gives no access to the bytes by itself.
unsafe impl Sync for Region {}

impl Region {
    /// The first byte of the data pages.
    ///
    /// # Panics
    ///
    /// In a child forked after the region was made, where its memory is not mapped.
    pub(crate) fn as_ptr(&self) -> *mut u8 {
        assert!(
            self.in_this_process(),
            "protected memory made before fork is not mapped in the child"
        );
        self.data.as_ptr()
    }

    /// Whether this process made the region, rather than inheriting it across `fork`.
    pub(crate) fn in_this_process(&self) -> bool {
        self.generation == fork_generation::current()
    }

    /// The first data byte, to wipe the bytes, if they are this process's memory: always where
    /// the region was made; in a forked child only for [`Level::Heap`], whose bytes are the
    /// child's own copy-on-write copy, never for a mapping, which the child does not have.
    pub(crate) fn wipeable_ptr(&self) -> Option<*mut u8> {
        let ours = self.in_this_process() || matches!(self.backing, Backing::Heap(_));
        ours.then_some(self.data.as_ptr())
    }

    /// Makes the region look inherited across `fork`, for tests of what a forked child does.
    #[cfg(test)]
    pub(crate) fn pretend_inherited(&mut self) {
        self.generation = self.generation.of_another_process();
    }

    /// Bytes in the data pages.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// The protection the mapping got.
    pub(crate) const fn level(&self) -> Level {
        self.level
    }

    /// The unit regions are sized in: on Linux the system page size; elsewhere and under Miri
    /// 4096, the block size of the heap backing, not the system's page size.
    ///
    /// Off Linux every region is a heap allocation aligned to this block, which needs no real
    /// page size: 4096 keeps arenas and buffers the same shape on every platform and meets the
    /// 4 KiB alignment `SecretVec` asserts. A port that maps pages (A11, A12) must query the OS
    /// instead: Apple Silicon has 16 KiB pages, and Windows reserves memory in 64 KiB units
    /// (its allocation granularity).
    pub(crate) fn page_size() -> usize {
        #[cfg(all(target_os = "linux", not(miri)))]
        {
            rustix::param::page_size()
        }
        #[cfg(not(all(target_os = "linux", not(miri))))]
        {
            4096
        }
    }

    /// Whether `pages` data pages and their two guard pages stay within `isize::MAX` bytes, the
    /// most [`new`](Region::new) maps. Callers check this first and report
    /// [`MemError::TooLarge`](crate::secure_mem::MemError::TooLarge), which no level can help.
    pub(crate) fn fits(pages: NonZeroUsize) -> bool {
        Self::sizes(pages).is_some()
    }

    /// The bytes of `pages` data pages, and of the whole mapping with its two guard pages;
    /// `None` if the mapping would pass `isize::MAX` bytes.
    fn sizes(pages: NonZeroUsize) -> Option<(usize, usize)> {
        let page = Self::page_size();
        let len = pages.get().checked_mul(page)?;
        let total = page
            .checked_mul(2)
            .and_then(|guards| len.checked_add(guards))
            .filter(|total| isize::try_from(*total).is_ok())?;
        Some((len, total))
    }

    /// `pages` data pages at `level`, or why that level is not available here.
    ///
    /// A page count that does not [`fit`](Region::fits) is refused at every level.
    /// [`Level::Secret`] and [`Level::Locked`] are checked against `budget`'s share of this
    /// process's `RLIMIT_MEMLOCK` first, as a hint. The kernel's own
    /// accounting decides: a refused lock falls back, and every page of a secret mapping is
    /// faulted in here through a system call, so a kernel that charges secret pages when they
    /// are first touched refuses here with [`Refusal::LockLimit`] instead of raising `SIGBUS` at
    /// a later write.
    #[cfg_attr(
        not(all(target_os = "linux", not(miri))),
        expect(unused_variables, reason = "only mappings are charged to a budget")
    )]
    pub(crate) fn new(level: Level, pages: NonZeroUsize, budget: Budget) -> Result<Self, Refusal> {
        // First, so a forked child has cleared its inherited lock budget before it charges.
        let generation = fork_generation::current();
        // Callers check `fits` first, so this refusal is only a second line of defence.
        #[cfg_attr(
            not(all(target_os = "linux", not(miri))),
            expect(unused_variables, reason = "only mappings have guard pages")
        )]
        let (len, total) = Self::sizes(pages).ok_or(Refusal::Kernel)?;
        match level {
            Level::Heap => Self::heap(len, generation),
            #[cfg(all(target_os = "linux", not(miri)))]
            Level::Secret => mapping::secret(len, total, budget, generation),
            #[cfg(all(target_os = "linux", not(miri)))]
            Level::Locked | Level::DumpExcluded => {
                mapping::anonymous(len, total, level, budget, generation)
            }
            #[cfg(not(all(target_os = "linux", not(miri))))]
            Level::Secret | Level::Locked | Level::DumpExcluded => Err(Refusal::Platform),
        }
    }

    /// Ordinary heap memory, page-aligned so any element type fits.
    fn heap(len: usize, generation: Generation) -> Result<Self, Refusal> {
        let layout =
            Layout::from_size_align(len, Self::page_size()).map_err(|_| Refusal::Kernel)?;
        // SAFETY: `layout` has a non-zero size: `new` passes at least one whole page.
        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        let data = NonNull::new(ptr).ok_or(Refusal::Kernel)?;
        Ok(Self {
            data,
            len,
            level: Level::Heap,
            generation,
            backing: Backing::Heap(layout),
        })
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        let Some(data) = self.wipeable_ptr() else {
            // An inherited mapping in a forked child: it stayed with the parent, which wipes and
            // frees it. The address here is unmapped or someone else's, so leave it.
            return;
        };
        // SAFETY: `data` points at `len` bytes this region owns and this process has
        // (`wipeable_ptr`: made here, or a heap copy private to this forked child), and no
        // reference into them outlives the region: slots and buffers hold the region alive while
        // they exist.
        let bytes = unsafe { std::slice::from_raw_parts_mut(data, self.len) };
        bytes.zeroize();
        // Test seam: the freed memory cannot be read once it is unmapped or deallocated, so
        // tests see it here, after the wipe and just before the free.
        #[cfg(test)]
        tests::WIPED_AT_FREE.set(Some(bytes.iter().all(|byte| *byte == 0)));
        match self.backing {
            #[cfg(all(target_os = "linux", not(miri)))]
            Backing::Mapped {
                base,
                total,
                charged,
                budget,
            } => mapping::unmap(base, total, charged, budget),
            // SAFETY: allocated in `heap` with exactly this layout and not freed since.
            Backing::Heap(layout) => unsafe { alloc::dealloc(data, layout) },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    std::thread_local! {
        /// Set by each `Region` this thread drops, just before its memory is freed: whether
        /// every data byte was zero by then. `None` until a region is freed.
        pub(super) static WIPED_AT_FREE: Cell<Option<bool>> = const { Cell::new(None) };
    }

    fn pages(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("tests map at least one page")
    }

    /// Every level this build can map, filled with non-zero bytes and dropped, is all zero by
    /// the time its memory is unmapped or deallocated.
    #[test]
    fn regions_are_wiped_before_they_are_freed() {
        for level in [
            Level::Heap,
            Level::DumpExcluded,
            Level::Locked,
            Level::Secret,
        ] {
            let region = match Region::new(level, pages(2), Budget::Keys) {
                Ok(region) => region,
                #[cfg(all(target_os = "linux", not(miri)))]
                Err(refusal) if level == Level::Secret => {
                    skip(&format!("memfd_secret: {refusal:?}"));
                    continue;
                }
                #[cfg(not(all(target_os = "linux", not(miri))))]
                Err(Refusal::Platform) if level != Level::Heap => continue,
                Err(refusal) => panic!("{level}: {refusal:?}"),
            };
            write_and_read(&region);
            WIPED_AT_FREE.set(None);
            drop(region);
            assert_eq!(WIPED_AT_FREE.take(), Some(true), "{level}");
        }
    }

    fn write_and_read(region: &Region) {
        // SAFETY: the test owns the whole region and holds no other reference into it.
        let bytes = unsafe { std::slice::from_raw_parts_mut(region.as_ptr(), region.len()) };
        assert!(bytes.iter().all(|byte| *byte == 0), "new memory is zeroed");
        bytes.fill(0xa5);
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn a_forked_child_wipes_and_frees_its_copy_of_a_heap_region() {
        let mut region =
            Region::new(Level::Heap, pages(1), Budget::Keys).expect("the heap is always available");
        write_and_read(&region);
        region.pretend_inherited();
        assert!(!region.in_this_process());
        assert!(
            region.wipeable_ptr().is_some(),
            "a heap copy is the child's own memory"
        );
        WIPED_AT_FREE.set(None);
        drop(region);
        assert_eq!(
            WIPED_AT_FREE.take(),
            Some(true),
            "wiped before it was freed"
        );
    }

    #[test]
    #[should_panic(expected = "not mapped in the child")]
    fn a_forked_child_cannot_use_an_inherited_heap_region() {
        let mut region =
            Region::new(Level::Heap, pages(1), Budget::Keys).expect("the heap is always available");
        region.pretend_inherited();
        region.as_ptr();
    }

    /// A mapping is not in a forked child at all (`MADV_DONTFORK`), so the child must neither
    /// wipe nor unmap the address, which may hold another mapping by then.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn a_forked_child_leaves_an_inherited_mapping_alone() {
        let mut region = Region::new(Level::DumpExcluded, pages(1), Budget::Keys)
            .expect("anonymous mappings work");
        let made_here = region.generation;
        region.pretend_inherited();
        assert_eq!(region.wipeable_ptr(), None);
        region.generation = made_here;
        assert!(region.wipeable_ptr().is_some(), "the maker wipes it");
    }

    #[test]
    fn heap_regions_are_page_aligned_and_usable() {
        let region =
            Region::new(Level::Heap, pages(2), Budget::Keys).expect("the heap is always available");
        assert_eq!(region.level(), Level::Heap);
        assert_eq!(region.len(), 2 * Region::page_size());
        assert_eq!(region.as_ptr().addr() % Region::page_size(), 0);
        write_and_read(&region);
    }

    #[test]
    fn page_counts_past_the_address_space_are_refused_at_every_level() {
        let page = Region::page_size();
        let largest = isize::MAX.unsigned_abs() / page;
        // The data alone overflows; the guards overflow; the guards pass `isize::MAX`.
        for count in [usize::MAX, usize::MAX / page, largest, largest - 1] {
            assert!(!Region::fits(pages(count)), "{count} pages");
            for level in [
                Level::Heap,
                Level::DumpExcluded,
                Level::Locked,
                Level::Secret,
            ] {
                assert_eq!(
                    Region::new(level, pages(count), Budget::Keys).err(),
                    Some(Refusal::Kernel),
                    "{level} with {count} pages"
                );
            }
        }
        assert!(
            Region::fits(pages(largest - 2)),
            "the largest count whose guards still fit"
        );
    }

    /// Skips the rest of a test, saying why, or fails it where `CRYPTHIX_REQUIRE_SECRETMEM=1`
    /// says the system has secret memory. That memory counts against `RLIMIT_MEMLOCK`, so a
    /// system that must have it must also leave room to lock.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[expect(clippy::print_stderr, reason = "a skipped check says so")]
    fn skip(why: &str) {
        assert!(
            std::env::var_os("CRYPTHIX_REQUIRE_SECRETMEM").is_none_or(|value| value != "1"),
            "{why}, but CRYPTHIX_REQUIRE_SECRETMEM=1"
        );
        eprintln!("{why}; skipped");
    }

    /// The bytes of the lock budget a region holds, and the share they count against.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn charged(region: &Region) -> (usize, Option<Budget>) {
        match region.backing {
            Backing::Mapped {
                charged, budget, ..
            } => (charged, Some(budget)),
            Backing::Heap(_) => (0, None),
        }
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn secret_mappings_charge_their_guard_pages_and_locked_ones_only_data() {
        let page = Region::page_size();
        match Region::new(Level::Secret, pages(2), Budget::Keys) {
            Ok(secret) => assert_eq!(
                charged(&secret),
                (4 * page, Some(Budget::Keys)),
                "two data pages, two guards"
            ),
            Err(refusal) => skip(&format!("memfd_secret: {refusal:?}")),
        }
        let anonymous =
            Region::new(Level::Locked, pages(2), Budget::Buffers).expect("anonymous mappings work");
        let expected = if anonymous.level() == Level::Locked {
            2 * page
        } else {
            0
        };
        assert_eq!(
            charged(&anonymous),
            (expected, Some(Budget::Buffers)),
            "mlock charges the data pages only, to the budget asked for"
        );
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn every_mapped_level_is_usable_or_refused_cleanly() {
        for level in [Level::DumpExcluded, Level::Locked, Level::Secret] {
            match Region::new(level, pages(1), Budget::Keys) {
                Ok(region) => {
                    assert!(region.level() <= level);
                    write_and_read(&region);
                }
                Err(refusal) => assert_ne!(level, Level::DumpExcluded, "{refusal:?}"),
            }
        }
    }

    /// The value of `field` (such as `VmFlags` or `Rss`) for the mapping that holds `address`,
    /// from `/proc/self/smaps`.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn smaps_field(address: usize, field: &str) -> String {
        let smaps = std::fs::read_to_string("/proc/self/smaps").expect("procfs is mounted");
        let mut inside = false;
        for line in smaps.lines() {
            let first = line.split_whitespace().next().unwrap_or_default();
            if let Some((start, end)) = first.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                inside = (start..end).contains(&address);
            } else if inside
                && let Some((name, value)) = line.split_once(':')
                && name == field
            {
                return value.trim().to_owned();
            }
        }
        panic!("no mapping holds the region, or it has no {field}");
    }

    /// The `VmFlags` of the mapping that holds `address`.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn vm_flags(address: usize) -> Vec<String> {
        smaps_field(address, "VmFlags")
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    }

    /// A secret region is resident from the moment it is made, before anything writes to it:
    /// every data page was faulted in through the kernel, so a page the kernel will not back
    /// failed then, not at a later write (as `SIGBUS`). The data pages are a mapping of their
    /// own between the guards, so its `Rss` is exactly the data.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn secret_regions_are_faulted_in_when_they_are_made() {
        let region = match Region::new(Level::Secret, pages(3), Budget::Keys) {
            Ok(region) => region,
            Err(refusal) => return skip(&format!("memfd_secret: {refusal:?}")),
        };
        let rss = smaps_field(region.as_ptr().addr(), "Rss");
        let kib: usize = rss
            .strip_suffix(" kB")
            .and_then(|kib| kib.parse().ok())
            .unwrap_or_else(|| panic!("an Rss in kB: {rss}"));
        assert_eq!(kib * 1024, region.len(), "resident before any write");
    }

    /// Every mapped level, with a guard page on each side of the data that cannot be read.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn mapped_levels_are_out_of_dumps_and_forks_and_locked_when_they_say_so() {
        for level in [Level::DumpExcluded, Level::Locked, Level::Secret] {
            let region = match Region::new(level, pages(1), Budget::Keys) {
                Ok(region) => region,
                Err(refusal) => {
                    skip(&format!("{level}: {refusal:?}"));
                    continue;
                }
            };
            let flags = vm_flags(region.as_ptr().addr());
            assert!(
                flags.iter().any(|flag| flag == "dd"),
                "{level}: not dump-excluded"
            );
            assert!(
                flags.iter().any(|flag| flag == "dc"),
                "{level}: copied on fork"
            );
            if region.level() == Level::Locked {
                assert!(
                    flags.iter().any(|flag| flag == "lo"),
                    "locked but no `lo` flag"
                );
            }
            let below = vm_flags(region.as_ptr().addr() - Region::page_size());
            assert!(
                !below.iter().any(|flag| flag == "rd"),
                "{level}: the guard page below is readable"
            );
            let above = vm_flags(region.as_ptr().addr() + region.len());
            assert!(
                !above.iter().any(|flag| flag == "rd"),
                "{level}: the guard page above is readable"
            );
        }
    }

    /// A lock that quietly failed would pass the checks above as `DumpExcluded`, so where the
    /// limit leaves room, `Locked` must be what a key region or a plaintext buffer asking for
    /// it gets. The room asked for is far more than the page locked here, so what tests running
    /// at the same time lock leaves it: a few key pages, and buffers of up to 64 KiB.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn locked_memory_is_locked_where_the_limit_has_room() {
        use crate::secure_mem::{SecretBuf, lock_budget};

        let has_room = |budget: Budget, pages: usize| {
            let (room, needed) = (lock_budget::room(budget), pages * Region::page_size());
            let enough = room >= needed;
            if !enough {
                skip(&format!(
                    "RLIMIT_MEMLOCK leaves {budget:?} {room} bytes to lock, under {needed}"
                ));
            }
            enough
        };
        let locked = |address: usize| vm_flags(address).iter().any(|flag| flag == "lo");
        if has_room(Budget::Keys, 16) {
            let region = Region::new(Level::Locked, pages(1), Budget::Keys)
                .expect("anonymous mappings work");
            assert_eq!(region.level(), Level::Locked);
            assert!(
                locked(region.as_ptr().addr()),
                "a key region has no `lo` flag"
            );
        }
        if has_room(Budget::Buffers, 256) {
            let buf = SecretBuf::try_zeroed(10).expect("memory for a buffer");
            assert_eq!(buf.level(), Some(Level::Locked));
            assert!(locked(buf.as_ptr().addr()), "a buffer has no `lo` flag");
        }
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn secret_pages_cannot_be_read_through_proc_mem_but_dump_excluded_ones_can() {
        use std::io::{Read, Seek, SeekFrom};

        let read = |region: &Region| {
            let mut mem = std::fs::File::open("/proc/self/mem").expect("procfs is mounted");
            mem.seek(SeekFrom::Start(region.as_ptr().addr() as u64))
                .expect("seek");
            let mut byte = [0u8; 1];
            mem.read_exact(&mut byte).map(|()| byte[0])
        };
        let excluded = Region::new(Level::DumpExcluded, pages(1), Budget::Keys)
            .expect("anonymous mappings work");
        assert_eq!(read(&excluded).ok(), Some(0), "the probe itself works");
        match Region::new(Level::Secret, pages(1), Budget::Keys) {
            Ok(secret) => assert!(read(&secret).is_err(), "secret memory was readable"),
            Err(refusal) => skip(&format!("memfd_secret: {refusal:?}")),
        }
    }

    /// `process_vm_readv(2)` pins the pages it reads (`get_user_pages`), which secret memory
    /// refuses with `EFAULT`, as the kernel's `memfd_secret` selftest checks
    /// (`tools/testing/selftests/mm/memfd_secret.c`, `test_vmsplice` and `test_process_vm_read`).
    /// Read from this process itself, which needs no ptrace permission.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn secret_pages_cannot_be_read_by_process_vm_readv_but_dump_excluded_ones_can() {
        let read = |region: &Region| {
            let mut byte = [0u8; 1];
            let local = libc::iovec {
                iov_base: byte.as_mut_ptr().cast(),
                iov_len: 1,
            };
            let remote = libc::iovec {
                iov_base: region.as_ptr().cast(),
                iov_len: 1,
            };
            // SAFETY: the call writes at most one byte, into `byte`; it only reads `remote`,
            // through the kernel, which fails rather than faults on memory it cannot read.
            let read = unsafe {
                libc::process_vm_readv(libc::getpid(), &raw const local, 1, &raw const remote, 1, 0)
            };
            match read {
                1 => Ok(byte[0]),
                _ => Err(std::io::Error::last_os_error().raw_os_error()),
            }
        };
        let excluded = Region::new(Level::DumpExcluded, pages(1), Budget::Keys)
            .expect("anonymous mappings work");
        // SAFETY: the test owns the region and holds no other reference into it.
        unsafe { excluded.as_ptr().write(0x5a) };
        assert_eq!(read(&excluded), Ok(0x5a), "the probe itself works");
        match Region::new(Level::Secret, pages(1), Budget::Keys) {
            Ok(secret) => assert_eq!(read(&secret), Err(Some(libc::EFAULT))),
            Err(refusal) => skip(&format!("memfd_secret: {refusal:?}")),
        }
    }

    #[cfg(not(all(target_os = "linux", not(miri))))]
    #[test]
    fn only_the_heap_exists_here() {
        for level in [Level::DumpExcluded, Level::Locked, Level::Secret] {
            for budget in [Budget::Keys, Budget::Buffers] {
                assert_eq!(
                    Region::new(level, pages(1), budget).err(),
                    Some(Refusal::Platform),
                    "{level} for {budget:?}"
                );
            }
        }
    }
}
