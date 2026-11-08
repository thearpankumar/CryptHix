//! Mapping, guarding, locking and unmapping secret memory on Linux.
#![expect(
    unsafe_code,
    reason = "mapping, protecting and freeing memory has no safe interface"
)]

use std::ffi::c_void;
use std::io;
use std::mem::ManuallyDrop;
use std::ptr::{self, NonNull};

use rustix::mm::{self, Advice, MapFlags, MprotectFlags, ProtFlags};

use crate::secure_mem::Level;
use crate::secure_mem::fork_generation::Generation;
use crate::secure_mem::lock_budget::{self, Budget};
use crate::secure_mem::memfd_secret;
use crate::secure_mem::region::Refusal;
use crate::secure_mem::region::region::{Backing, Region};

/// A `memfd_secret` mapping of `len` data bytes in `total`, every page faulted in.
pub(super) fn secret(
    len: usize,
    total: usize,
    budget: Budget,
    generation: Generation,
) -> Result<Region, Refusal> {
    // The whole mapping, guard pages included: exact where the kernel checks the mapping when
    // it is mapped, a small over-charge where it charges pages as they are faulted in (see
    // `lock_budget::try_charge`).
    if !lock_budget::try_charge(budget, total) {
        return Err(Refusal::LockLimit);
    }
    // On failure no region holds the charge yet, so it is returned here.
    map_secret(len, total, budget, generation).inspect_err(|_| lock_budget::release(budget, total))
}

fn map_secret(
    len: usize,
    total: usize,
    budget: Budget,
    generation: Generation,
) -> Result<Region, Refusal> {
    let fd = memfd_secret::open().map_err(|error| open_refusal(&error))?;
    let file_len = u64::try_from(total).map_err(|_| Refusal::Kernel)?;
    // Sizing the file charges nothing: the kernel's `secretmem_setattr` only refuses a
    // second size, so every error here is the kernel's.
    rustix::fs::ftruncate(&fd, file_len).map_err(|_| Refusal::Kernel)?;
    // SAFETY: a new shared mapping at an address the kernel picks, of a file only this
    // process holds; it aliases no existing memory. The file stays alive with the mapping
    // after `fd` is closed.
    let base = unsafe {
        mm::mmap(
            ptr::null_mut(),
            total,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::SHARED,
            &fd,
            0,
        )
    }
    .map_err(mmap_refusal)?;
    let mapping = Mapping::new(base, total)?;
    mapping.guard(len)?;
    mapping.fault_in(len)?;
    // From here the region owns the charge and returns it when dropped.
    Ok(mapping.into_region(len, Level::Secret, total, budget, generation))
}

/// Sorts an error of `mmap(2)` on a `memfd_secret` file. `EAGAIN` is the lock limit, as
/// `mmap(2)` lists it ("too much memory has been locked"): kernels such as 5.14 and 6.6
/// check the whole mapping against `RLIMIT_MEMLOCK` when it is mapped (`secretmem_mmap` in
/// `mm/secretmem.c` returns `-EAGAIN` when `mlock_future_check`/`mlock_future_ok` fails).
/// Current mainline charges each page when it is faulted in instead, which
/// `Mapping::fault_in` reports. `ENOMEM` is not the lock limit here: the address space,
/// `vm.max_map_count` or the kernel's memory ran out, so it, like every other error, is the
/// kernel's refusal.
fn mmap_refusal(error: rustix::io::Errno) -> Refusal {
    if error == rustix::io::Errno::AGAIN {
        Refusal::LockLimit
    } else {
        Refusal::Kernel
    }
}

/// Sorts an error of `memfd_secret(2)`: `ENOSYS` (disabled, or a kernel before 5.14) and
/// `EPERM` (a seccomp filter) mean the system has no secret memory; anything else, such as
/// `EMFILE`, `ENFILE` or `ENOMEM`, is a failure of this one call. `EINVAL` is defined as
/// unknown flag bits, which this crate never passes (its only flag, `O_CLOEXEC`, exists
/// since 5.14), so it is sorted as unsupported defensively: a kernel that rejects the call
/// that way gives no secret memory either.
fn open_refusal(error: &io::Error) -> Refusal {
    match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EPERM | libc::EINVAL) => Refusal::Unsupported,
        _ => Refusal::Kernel,
    }
}

/// A private anonymous mapping of `len` data bytes in `total`, locked if `level` is
/// [`Level::Locked`] and `budget`'s share of the limit allows; otherwise
/// [`Level::DumpExcluded`].
pub(super) fn anonymous(
    len: usize,
    total: usize,
    level: Level,
    budget: Budget,
    generation: Generation,
) -> Result<Region, Refusal> {
    // SAFETY: a new private anonymous mapping at an address the kernel picks; it aliases no
    // existing memory.
    let base = unsafe {
        mm::mmap_anonymous(
            ptr::null_mut(),
            total,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE,
        )
    }
    .map_err(|_| Refusal::Kernel)?;
    let mapping = Mapping::new(base, total)?;
    mapping.guard(len)?;
    let mut region = mapping.into_region(len, Level::DumpExcluded, 0, budget, generation);
    // `mlock` charges only the data pages it locks.
    if level == Level::Locked && lock(&region, budget) {
        region.level = Level::Locked;
        if let Backing::Mapped { charged, .. } = &mut region.backing {
            *charged = len;
        }
    }
    Ok(region)
}

/// A new mapping of `total` bytes that holds nothing yet, unmapped without a wipe if
/// setting it up fails: a wipe would touch secret pages that may not be faulted in.
struct Mapping {
    base: NonNull<u8>,
    total: usize,
}

impl Mapping {
    /// Takes ownership of the mapping `mmap` returned at `base`.
    fn new(base: *mut c_void, total: usize) -> Result<Self, Refusal> {
        let base = NonNull::new(base.cast::<u8>()).ok_or(Refusal::Kernel)?;
        Ok(Self { base, total })
    }

    /// The first data byte, one page past the start.
    fn data(&self) -> *mut u8 {
        // SAFETY: `Region::new` made `total` at least two pages more than the data, so one
        // page past `base` is inside the mapping.
        unsafe { self.base.as_ptr().add(Region::page_size()) }
    }

    /// Makes the first page and the page after `len` data bytes inaccessible, and keeps the
    /// data pages out of core dumps and forked children.
    fn guard(&self, len: usize) -> Result<(), Refusal> {
        let page = Region::page_size();
        let data = self.data().cast::<c_void>();
        // SAFETY: both guards and the data pages lie inside this mapping, which nothing
        // else refers to.
        let advised = unsafe {
            mm::mprotect(self.base.as_ptr().cast(), page, MprotectFlags::empty()).is_ok()
                && mm::mprotect(data.byte_add(len), page, MprotectFlags::empty()).is_ok()
                && mm::madvise(data, len, Advice::LinuxDontDump).is_ok()
                && mm::madvise(data, len, Advice::LinuxDontFork).is_ok()
        };
        if advised {
            Ok(())
        } else {
            Err(Refusal::Kernel)
        }
    }

    /// Faults in each of the first `len` data bytes' pages by having the `getrandom(2)`
    /// system call write one byte to it, then zeroes that byte again.
    ///
    /// The kernel copies into the page, so a fault it will not back (on kernels that charge
    /// secret pages to `RLIMIT_MEMLOCK` when first touched, a page past the limit) comes
    /// back as `EFAULT` and becomes [`Refusal::LockLimit`]. A plain write would instead
    /// raise `SIGBUS` (`secretmem_fault` returns `VM_FAULT_SIGBUS`) and kill the process.
    /// `MADV_POPULATE_WRITE` is no alternative: secret mappings refuse it with `EINVAL`.
    /// This relies on copying system calls reaching secret pages, as the
    /// [`secure_mem`](crate::secure_mem#why-plaintext-stays-out-of-secret-memory) docs
    /// explain, with what an `EFAULT` here would mean if a kernel refused them.
    ///
    /// It must be the raw system call, never libc's `getrandom` (nor `rustix`'s, which calls
    /// libc's where it is built on libc): since glibc 2.41, on kernels with the vDSO
    /// `getrandom` of Linux 6.11, the libc function generates the bytes in user mode and stores
    /// them with an ordinary write (glibc commit "linux: Add support for getrandom vDSO",
    /// [libc-alpha, 2024][vdso]; glibc 2.41 NEWS: it "might not issue a syscall"). That write
    /// is exactly the faulting store this function exists to avoid, and would raise `SIGBUS`
    /// again.
    ///
    /// [vdso]: https://sourceware.org/pipermail/libc-alpha/2024-September/159978.html
    fn fault_in(&self, len: usize) -> Result<(), Refusal> {
        self.fault_in_with(len, write_random_byte)
    }

    /// [`fault_in`](Self::fault_in) with `write` standing in for the system call, so tests can
    /// interrupt it.
    fn fault_in_with(
        &self,
        len: usize,
        write: unsafe fn(*mut u8) -> io::Result<()>,
    ) -> Result<(), Refusal> {
        for offset in (0..len).step_by(Region::page_size()) {
            // SAFETY: `offset` is below `len`, so the byte is inside the data pages.
            let byte = unsafe { self.data().add(offset) };
            loop {
                // SAFETY: `byte` lies in this mapping and is referred to by nothing else.
                match unsafe { write(byte) } {
                    Ok(()) => break,
                    // `getrandom(2)` blocks until the kernel's generator is ready, and a signal
                    // handler can interrupt that wait.
                    Err(error) => match error.raw_os_error() {
                        Some(libc::EINTR) => {}
                        Some(libc::EFAULT) => return Err(Refusal::LockLimit),
                        _ => return Err(Refusal::Kernel),
                    },
                }
            }
            // SAFETY: the call above faulted the page in, and secret and anonymous pages
            // stay mapped until `munmap`, so this write to a writable data byte cannot fault.
            unsafe { byte.write(0) };
        }
        Ok(())
    }

    /// The region of `generation` the set-up mapping becomes, holding `charged` bytes of
    /// `budget`.
    fn into_region(
        self,
        len: usize,
        level: Level,
        charged: usize,
        budget: Budget,
        generation: Generation,
    ) -> Region {
        let mapping = ManuallyDrop::new(self);
        Region {
            // SAFETY: `data` is one page into a mapping that starts at a non-null address.
            data: unsafe { NonNull::new_unchecked(mapping.data()) },
            len,
            level,
            generation,
            backing: Backing::Mapped {
                base: mapping.base,
                total: mapping.total,
                charged,
                budget,
            },
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // Nothing is charged yet, so the budget named is never touched.
        unmap(self.base, self.total, 0, Budget::Keys);
    }
}

/// Has the raw `getrandom(2)` system call write one byte at `byte`, which the kernel copies
/// in, so an unbacked page fails with `EFAULT` instead of faulting this process.
///
/// # Safety
///
/// `byte` must lie in a mapping of this process that nothing else refers to.
unsafe fn write_random_byte(byte: *mut u8) -> io::Result<()> {
    // `getrandom(2)` takes `unsigned int` flags; none are needed.
    let flags: libc::c_uint = 0;
    // SAFETY: the system call writes at most one byte, at `byte`, which the caller vouches
    // for.
    let filled = unsafe { libc::syscall(libc::SYS_getrandom, byte, 1_usize, flags) };
    match filled {
        1 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other("getrandom wrote other than one byte")),
    }
}

/// Locks the data pages within `budget`'s share of the limit; `false` leaves them unlocked
/// and uncharged.
fn lock(region: &Region, budget: Budget) -> bool {
    if !lock_budget::try_charge(budget, region.len) {
        return false;
    }
    // SAFETY: the data pages belong to `region`'s mapping.
    let locked = unsafe { mm::mlock(region.as_ptr().cast(), region.len) }.is_ok();
    if !locked {
        lock_budget::release(budget, region.len);
    }
    locked
}

/// Unmaps a whole mapping and returns its charge to `budget`.
pub(super) fn unmap(base: NonNull<u8>, total: usize, charged: usize, budget: Budget) {
    // SAFETY: `base` and `total` describe exactly one mapping made in this module, which is
    // being dropped, so nothing refers to it any more. Unmapping also unlocks it.
    let unmapped = unsafe { mm::munmap(base.as_ptr().cast(), total) };
    debug_assert!(unmapped.is_ok(), "munmap of an owned mapping cannot fail");
    lock_budget::release(budget, charged);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_missing_memfd_secret_is_unsupported() {
        for (errno, refusal) in [
            (libc::ENOSYS, Refusal::Unsupported),
            (libc::EPERM, Refusal::Unsupported),
            (libc::EINVAL, Refusal::Unsupported),
            (libc::EMFILE, Refusal::Kernel),
            (libc::ENFILE, Refusal::Kernel),
            (libc::ENOMEM, Refusal::Kernel),
        ] {
            let error = std::io::Error::from_raw_os_error(errno);
            assert_eq!(open_refusal(&error), refusal, "{error}");
        }
        let not_os = std::io::Error::from(std::io::ErrorKind::InvalidData);
        assert_eq!(open_refusal(&not_os), Refusal::Kernel);
    }

    /// Only `EAGAIN` from mapping a secret file is the lock limit; `ENOMEM` (no address space
    /// or memory) and the rest are the kernel's.
    #[test]
    fn only_eagain_from_mapping_secret_memory_is_the_lock_limit() {
        use rustix::io::Errno;

        for (errno, refusal) in [
            (Errno::AGAIN, Refusal::LockLimit),
            (Errno::NOMEM, Refusal::Kernel),
            (Errno::INVAL, Refusal::Kernel),
            (Errno::NODEV, Refusal::Kernel),
            (Errno::PERM, Refusal::Kernel),
        ] {
            assert_eq!(mmap_refusal(errno), refusal, "{errno}");
        }
    }

    /// A page the kernel will not back must come back as an error, not a signal. An
    /// inaccessible page fails the same way an uncharged secret page does on kernels that
    /// charge at fault time.
    #[test]
    fn faulting_in_an_unbacked_page_is_a_lock_limit_refusal_not_a_signal() {
        let page = Region::page_size();
        let len = 2 * page;
        let mapping = anonymous_mapping(4 * page);
        mapping.guard(len).expect("guards can be set");
        // SAFETY: the second data page lies inside the mapping, which only `mapping` owns.
        unsafe {
            mm::mprotect(
                mapping.data().add(page).cast(),
                page,
                MprotectFlags::empty(),
            )
        }
        .expect("a page of an own mapping can be protected");
        assert_eq!(mapping.fault_in(len), Err(Refusal::LockLimit));
        mapping
            .fault_in(page)
            .expect("an accessible page faults in");
        // SAFETY: the first data page is readable, faulted in above.
        let probe = unsafe { mapping.data().read() };
        assert_eq!(probe, 0, "the probe byte is zeroed again");
    }

    /// A system call interrupted by a signal is made again, not taken for a refusal.
    #[test]
    fn an_interrupted_fault_in_is_retried() {
        std::thread_local! {
            static INTERRUPTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }
        /// Fails with `EINTR` the first time on this thread, then writes the byte.
        unsafe fn interrupted_once(byte: *mut u8) -> io::Result<()> {
            if INTERRUPTED.replace(true) {
                // SAFETY: passed on from `fault_in_with`, which vouches for `byte`.
                unsafe { write_random_byte(byte) }
            } else {
                Err(io::Error::from_raw_os_error(libc::EINTR))
            }
        }

        let page = Region::page_size();
        let mapping = anonymous_mapping(3 * page);
        assert_eq!(mapping.fault_in_with(page, interrupted_once), Ok(()));
        assert!(INTERRUPTED.get(), "the stand-in was never called");
    }

    /// A mapping dropped before it becomes a region, as when setting it up fails, is unmapped.
    #[test]
    fn a_mapping_that_never_becomes_a_region_is_unmapped_when_dropped() {
        use std::io::{Read, Seek, SeekFrom};

        let marker = [0xA5_u8; 16];
        let mapping = anonymous_mapping(Region::page_size());
        let address = mapping.base.as_ptr().addr();
        // SAFETY: the first bytes of a new read-write mapping that only `mapping` owns.
        unsafe { mapping.base.as_ptr().cast::<[u8; 16]>().write(marker) };
        drop(mapping);
        // Another thread may map the freed range at once, but not with the marker in it.
        let mut mem = std::fs::File::open("/proc/self/mem").expect("procfs is mounted");
        mem.seek(SeekFrom::Start(address as u64)).expect("seek");
        let mut read = [0_u8; 16];
        let still_mapped = mem.read_exact(&mut read).is_ok() && read == marker;
        assert!(!still_mapped, "the dropped mapping is still there");
    }

    /// A new private anonymous read-write mapping of `total` bytes.
    fn anonymous_mapping(total: usize) -> Mapping {
        // SAFETY: a new private anonymous mapping at an address the kernel picks.
        let base = unsafe {
            mm::mmap_anonymous(
                ptr::null_mut(),
                total,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE,
            )
        }
        .expect("anonymous mappings work");
        Mapping::new(base, total).expect("a non-null mapping")
    }
}
