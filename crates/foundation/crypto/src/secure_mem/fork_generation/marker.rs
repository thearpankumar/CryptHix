//! The `MADV_WIPEONFORK` marker page that holds the running process's generation on Linux.
#![expect(
    unsafe_code,
    reason = "mapping and advising the marker page has no safe interface"
)]

use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::thread;

use rustix::mm::{self, Advice, MapFlags, ProtFlags};

use crate::secure_mem::fork_generation::fork_generation;
use crate::secure_mem::fork_generation::fork_handler;
use crate::secure_mem::region::Region;

/// The marker word, at the start of a `MADV_WIPEONFORK` page: 0 in a process that has not
/// taken its generation yet, [`CLAIMED`] while one thread takes it, then the generation.
/// Null until the first call; [`no_marker`] where the page could not be set up.
static MARKER: AtomicPtr<AtomicU64> = AtomicPtr::new(ptr::null_mut());

/// What [`MARKER`] points at where there is no marker page; never read or written.
static NO_MARKER: AtomicU64 = AtomicU64::new(0);

/// The highest generation this process or any ancestor took; copied by `fork`, so a child
/// takes one above every generation its inherited regions can have.
static LATEST: AtomicU64 = AtomicU64::new(0);

/// The marker while one thread clears the inherited state and takes the next generation.
const CLAIMED: u64 = u64::MAX;

/// The running process's generation: the marker's, or the fork count where there is no marker
/// page.
pub(super) fn current() -> u64 {
    let marker = match MARKER.load(Ordering::Acquire) {
        seen if seen.is_null() => set_up(),
        seen => seen,
    };
    if ptr::eq(marker, no_marker()) {
        return fork_handler::forks();
    }
    // SAFETY: `marker` is the start of a page `set_up` mapped, which is never unmapped, and
    // that page is aligned for an `AtomicU64`.
    take_generation(
        unsafe { &*marker },
        &LATEST,
        fork_generation::forget_inherited,
    )
}

fn no_marker() -> *mut AtomicU64 {
    ptr::from_ref(&NO_MARKER).cast_mut()
}

/// The generation in `marker`, taken first, one above `latest`, if this process has none
/// yet.
///
/// The thread that swaps 0 for [`CLAIMED`] clears the inherited state (`forget`) before it
/// publishes the generation, so no thread charges a budget or records a level in this process
/// before that. Others wait the few stores it takes. A fork while it holds the claim does not
/// leave it stuck: the child's marker is zero again.
fn take_generation(marker: &AtomicU64, latest: &AtomicU64, forget: fn()) -> u64 {
    loop {
        match marker.load(Ordering::Acquire) {
            0 => {
                if marker
                    .compare_exchange(0, CLAIMED, Ordering::Acquire, Ordering::Acquire)
                    .is_ok()
                {
                    forget();
                    let next = latest.load(Ordering::Acquire) + 1;
                    // Before the marker, so a child forked in between still goes above it.
                    latest.store(next, Ordering::Release);
                    marker.store(next, Ordering::Release);
                    return next;
                }
            }
            CLAIMED => thread::yield_now(),
            generation => return generation,
        }
    }
}

/// Maps the marker page, or registers the fork handler if it cannot, and publishes whichever
/// the first thread to finish chose, so a process never mixes the two.
fn set_up() -> *mut AtomicU64 {
    let new = map_marker().unwrap_or_else(|| {
        // Before the choice is published, so no thread uses the counter unregistered.
        fork_handler::register_count_fork();
        no_marker()
    });
    match MARKER.compare_exchange(ptr::null_mut(), new, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => new,
        Err(won) => {
            if !ptr::eq(new, no_marker()) {
                // SAFETY: the page `map_marker` just mapped, never published, so nothing
                // refers to it.
                let unmapped = unsafe { mm::munmap(new.cast(), Region::page_size()) };
                debug_assert!(unmapped.is_ok(), "munmap of an own page cannot fail");
            }
            won
        }
    }
}

/// A zero page the kernel wipes in every child, or `None` on a kernel without
/// `MADV_WIPEONFORK` (before 4.14) or where the page cannot be mapped.
fn map_marker() -> Option<*mut AtomicU64> {
    let page = Region::page_size();
    // SAFETY: a new private anonymous mapping at an address the kernel picks; it aliases no
    // existing memory.
    let base = unsafe {
        mm::mmap_anonymous(
            ptr::null_mut(),
            page,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE,
        )
    }
    .ok()?;
    // SAFETY: advice on the page just mapped, which nothing else refers to. An advice value
    // no kernel knows must fail: some emulators (qemu user mode) accept every advice without
    // acting on it, as `BoringSSL`'s `fork_detect.cc` notes.
    let wipes = unsafe {
        libc::madvise(base, page, -1) != 0
            && mm::madvise(base, page, Advice::LinuxWipeOnFork).is_ok()
    };
    if wipes {
        Some(base.cast())
    } else {
        // SAFETY: the page mapped above, never published.
        let unmapped = unsafe { mm::munmap(base, page) };
        debug_assert!(unmapped.is_ok(), "munmap of an own page cannot fail");
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// The marker logic on words of its own, so the process-wide budget is left alone: a zero
    /// word takes the generation above the latest, clearing the inherited state once, and
    /// keeps it; a wiped word takes the next one.
    #[test]
    fn a_wiped_marker_takes_a_new_generation_and_clears_once() {
        static CLEARED: AtomicUsize = AtomicUsize::new(0);
        fn clear() {
            CLEARED.fetch_add(1, Ordering::AcqRel);
        }
        let (marker, latest) = (AtomicU64::new(0), AtomicU64::new(41));
        assert_eq!(take_generation(&marker, &latest, clear), 42);
        assert_eq!(take_generation(&marker, &latest, clear), 42);
        assert_eq!(CLEARED.load(Ordering::Acquire), 1, "cleared once");
        assert_eq!(latest.load(Ordering::Acquire), 42);
        marker.store(0, Ordering::Release);
        assert_eq!(take_generation(&marker, &latest, clear), 43);
        assert_eq!(CLEARED.load(Ordering::Acquire), 2);
    }
}
