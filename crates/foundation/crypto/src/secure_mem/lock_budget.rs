//! The bytes this process has locked, kept below `RLIMIT_MEMLOCK` before the kernel is asked.
//!
//! The limit is split in two: key arenas may lock up to the key reserve, and plaintext buffers
//! only what is left of the limit after it. So no amount of open plaintext (a large `open`, an
//! Argon2id run) can push the next key arena down a level, and since arenas are never unmapped,
//! keep it there. The reserve is what the process's key pool can ever charge: its configured
//! [`max_pages`](crate::secure_mem::Config::max_pages) plus two guard pages per arena
//! (`Config::lock_reserve`). Each charge reads it from that pool, which the first key or the
//! first plaintext buffer sets up if [`init`](crate::secure_mem::init) has not (`global`), so
//! no buffer is ever locked before the reserve it must leave is known, and the reserve never
//! changes once it is: an `init` after the first buffer is refused rather than given a larger
//! reserve that buffers already hold part of. When the limit is below the reserve, keys may
//! lock all of it and buffers none, so buffers are then left out of core dumps but not locked.
//!
//! The kernel counts one limit for both, so the split is this crate's own; the two shares add
//! up to at most the real limit. The budget is a hint that saves a doomed system call, not the
//! enforcement: the kernel's own accounting decides, and every refusal from it is handled (see
//! `Region::new`).
//!
//! The budget enforces the soft `RLIMIT_MEMLOCK` even for a process with `CAP_IPC_LOCK`, which
//! is conservative: [`mlock(2)`](https://man7.org/linux/man-pages/man2/mlock.2.html) says that
//! since Linux 2.6.9 "no limits are placed on the amount of memory that a privileged process can
//! lock", and kernels before the CVE-2026-93243 fix extended that to `memfd_secret` pages, so
//! such a process could lock more than this budget lets it. Patched kernels no longer exempt it
//! for secret memory, which they charge per user for as long as the pages exist
//! (upstream [commit 97d34aa65c29](https://git.kernel.org/linus/97d34aa65c29), Linux 7.3-rc2;
//! [Red Hat bug 2540263](https://bugzilla.redhat.com/show_bug.cgi?id=2540263),
//! [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-93243)), so the budget
//! is right there. Keeping to the limit costs a privileged
//! process at most a fall back to [`Level::DumpExcluded`](crate::secure_mem::Level::DumpExcluded)
//! for some buffers; an unlimited limit (`RLIM_INFINITY`) counts as `usize::MAX` bytes.
//!
//! Only Linux locks memory, so elsewhere and under Miri this is just [`Budget`], the share
//! named by every mapping; the arithmetic of the split is still built for tests there.

use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(all(target_os = "linux", not(miri)))]
use crate::secure_mem::global;

/// Which share of the limit a mapping is charged to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Budget {
    /// Key arenas, up to the key reserve.
    Keys,
    /// Plaintext buffers, up to what the key reserve leaves of the limit.
    Buffers,
}

/// Locked and secret bytes charged by the live key arenas of this process.
#[cfg(all(target_os = "linux", not(miri)))]
static KEYS: AtomicUsize = AtomicUsize::new(0);

/// Locked bytes charged by the live plaintext buffers of this process.
#[cfg(all(target_os = "linux", not(miri)))]
static BUFFERS: AtomicUsize = AtomicUsize::new(0);

/// Zeroes both counts when a forked child takes its generation (see `fork_generation`): none of
/// the parent's locked mappings exists in the child (`MADV_DONTFORK`, and `mlock` is not
/// inherited), so its counts would refuse the child what its own limit allows. The reserve
/// needs no reset: the child reads it from a pool of its own. Only atomic stores, so a
/// `pthread_atfork` child handler may call it.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn forget_inherited() {
    KEYS.store(0, Ordering::Release);
    BUFFERS.store(0, Ordering::Release);
}

/// Reserves `bytes` of `budget`'s share of the memory-lock limit, or returns `false` if they
/// would pass it.
///
/// Callers charge an `mlock` for the data pages it locks, as the kernel does, and a
/// `memfd_secret` mapping for all of it, guard pages included, on purpose. Kernels before the
/// CVE-2026-93243 fix check the whole mapping against the limit when it is mapped
/// (`secretmem_mmap` calls `mlock_future_ok` with the mapping's full length; [`mm/secretmem.c`
/// in v6.12][v6.12]), so there the charge is exact. Patched kernels charge each page when it is
/// first faulted in (`secretmem_fault` through `secretmem_account_folio`; [`mm/secretmem.c` in
/// mainline][mainline]), and the guard pages are never touched, so there it over-charges by two
/// pages an arena: a conservative hint that refuses a little early, never too late.
///
/// Memory other processes of the same user hold is not counted, though patched kernels count
/// it: they charge secret pages to the user (`user->locked_vm`), not the process. So a pass here
/// does not promise the kernel agrees: `Region::new` faults secret pages in through a system
/// call, which turns a refusal at fault time into an error instead of a `SIGBUS`. That path,
/// and the guard-page over-charge, are checked on a patched kernel by the `kernel-test` CI job
/// (`.github/workflows/kernel-test.yml`), whose test
/// `a_secret_arena_refused_at_fault_time_falls_back_to_locked` has another process of the user
/// hold secret pages so the kernel refuses an arena this budget lets through.
///
/// [v6.12]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/mm/secretmem.c?h=v6.12
/// [mainline]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/secretmem.c
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn try_charge(budget: Budget, bytes: usize) -> bool {
    charge_on(
        counter(budget),
        bytes,
        share(budget, limit(), global::key_lock_reserve()),
    )
}

/// Returns `bytes` reserved by [`try_charge`] on `budget` when their mapping is freed.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn release(budget: Budget, bytes: usize) {
    counter(budget).fetch_sub(bytes, Ordering::AcqRel);
}

#[cfg(all(target_os = "linux", not(miri)))]
fn counter(budget: Budget) -> &'static AtomicUsize {
    match budget {
        Budget::Keys => &KEYS,
        Budget::Buffers => &BUFFERS,
    }
}

/// The bytes of `limit` `budget` may lock when `reserve` is kept for keys: keys get the reserve
/// (or the whole limit, if it is smaller), buffers the rest. The two shares add up to `limit`.
#[cfg_attr(
    not(any(test, all(target_os = "linux", not(miri)))),
    expect(dead_code, reason = "only Linux locks memory")
)]
fn share(budget: Budget, limit: usize, reserve: usize) -> usize {
    let keys = reserve.min(limit);
    match budget {
        Budget::Keys => keys,
        Budget::Buffers => limit - keys,
    }
}

/// Adds `bytes` to `counter` if the total stays within `limit`; `false` leaves it unchanged.
#[cfg_attr(
    not(any(test, all(target_os = "linux", not(miri)))),
    expect(dead_code, reason = "only Linux locks memory")
)]
fn charge_on(counter: &AtomicUsize, bytes: usize, limit: usize) -> bool {
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |charged| {
            charge(charged, bytes, limit)
        })
        .is_ok()
}

/// `charged + bytes` if that stays within `limit`.
#[cfg_attr(
    not(any(test, all(target_os = "linux", not(miri)))),
    expect(dead_code, reason = "only Linux locks memory")
)]
fn charge(charged: usize, bytes: usize, limit: usize) -> Option<usize> {
    charged.checked_add(bytes).filter(|total| *total <= limit)
}

/// What `budget` may still lock in this process right now: its share of the limit less what is
/// already charged to it. Tests running at the same time may take some of it.
#[cfg(all(test, target_os = "linux", not(miri)))]
pub(crate) fn room(budget: Budget) -> usize {
    share(budget, limit(), global::key_lock_reserve())
        .saturating_sub(counter(budget).load(Ordering::Acquire))
}

/// The soft `RLIMIT_MEMLOCK` in bytes; `usize::MAX` when unlimited or unknown.
#[cfg(all(target_os = "linux", not(miri)))]
fn limit() -> usize {
    use rustix::process::{self, Resource};

    limit_bytes(process::getrlimit(Resource::Memlock).current)
}

/// A soft limit as `getrlimit` gives it (`None` for `RLIM_INFINITY`) in bytes: `usize::MAX`
/// when unlimited or past the address space.
#[cfg_attr(
    not(any(test, all(target_os = "linux", not(miri)))),
    expect(dead_code, reason = "only Linux locks memory")
)]
fn limit_bytes(current: Option<u64>) -> usize {
    current.map_or(usize::MAX, |bytes| {
        usize::try_from(bytes).unwrap_or(usize::MAX)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_charge_fits_up_to_the_limit_and_no_further() {
        assert_eq!(charge(4, 4, 8), Some(8));
        assert_eq!(charge(4, 5, 8), None);
        assert_eq!(
            charge(1, usize::MAX, usize::MAX),
            None,
            "overflow is refused"
        );
    }

    #[test]
    fn keys_get_their_reserve_and_buffers_only_the_rest() {
        assert_eq!(share(Budget::Keys, 100, 30), 30);
        assert_eq!(share(Budget::Buffers, 100, 30), 70);
        assert_eq!(
            share(Budget::Keys, 20, 30),
            20,
            "a limit below the reserve all goes to keys"
        );
        assert_eq!(share(Budget::Buffers, 20, 30), 0);
        assert_eq!(share(Budget::Keys, usize::MAX, 30), 30);
        assert_eq!(share(Budget::Buffers, usize::MAX, 30), usize::MAX - 30);
    }

    /// An unlimited `RLIMIT_MEMLOCK` (no limit, or `CAP_IPC_LOCK` with `RLIM_INFINITY`) is
    /// `usize::MAX` bytes: keys keep exactly their reserve, buffers may lock all the rest, and
    /// only an overflowing total is refused.
    #[test]
    fn an_unlimited_limit_still_splits_and_charges() {
        let unlimited = limit_bytes(None);
        assert_eq!(unlimited, usize::MAX);
        assert_eq!(limit_bytes(Some(4096)), 4096);
        assert_eq!(limit_bytes(Some(u64::MAX)), usize::MAX);
        let reserve = crate::secure_mem::Config::default().lock_reserve();
        let keys = share(Budget::Keys, unlimited, reserve);
        let buffers = share(Budget::Buffers, unlimited, reserve);
        assert_eq!(keys, reserve, "keys get their reserve, not the whole limit");
        assert_eq!(buffers, usize::MAX - reserve);
        let key_counter = AtomicUsize::new(0);
        assert!(charge_on(&key_counter, reserve, keys));
        assert!(
            !charge_on(&key_counter, 1, keys),
            "keys stop at the reserve"
        );
        let buffer_counter = AtomicUsize::new(0);
        let half = usize::MAX / 2;
        assert!(
            charge_on(&buffer_counter, half, buffers),
            "half the address space fits"
        );
        assert!(
            charge_on(&buffer_counter, buffers - half, buffers),
            "up to the limit"
        );
        assert!(
            !charge_on(&buffer_counter, 1, buffers),
            "the total cannot overflow"
        );
    }

    /// On a counter of its own, so neither this process's `RLIMIT_MEMLOCK` nor what other
    /// tests hold changes the outcome.
    #[test]
    fn charges_add_up_and_a_refused_one_changes_nothing() {
        let counter = AtomicUsize::new(0);
        assert!(charge_on(&counter, 3, 8));
        assert!(charge_on(&counter, 5, 8), "up to the limit exactly");
        assert!(!charge_on(&counter, 1, 8), "one past it");
        assert_eq!(
            counter.load(Ordering::Acquire),
            8,
            "the refusal took nothing"
        );
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn each_budget_counts_on_its_own_counter() {
        assert!(!std::ptr::eq(
            counter(Budget::Keys),
            counter(Budget::Buffers)
        ));
    }
}
