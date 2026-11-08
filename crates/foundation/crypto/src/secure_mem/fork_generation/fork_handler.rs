//! The `pthread_atfork` child handler that counts forks on kernels without `MADV_WIPEONFORK`.
#![expect(
    unsafe_code,
    reason = "registering a fork handler has no safe interface"
)]

use std::alloc::{self, Layout};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::secure_mem::fork_generation::fork_generation;

/// Forks counted by [`count_fork`], the generation where there is no marker page.
static FORKS: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    /// `pthread_atfork(3)`, which glibc and musl provide; the `libc` crate does not declare
    /// it for Linux.
    fn pthread_atfork(
        prepare: Option<unsafe extern "C" fn()>,
        parent: Option<unsafe extern "C" fn()>,
        child: Option<unsafe extern "C" fn()>,
    ) -> libc::c_int;
}

/// Has every later `fork` run [`count_fork`] in the child. Each call adds the handler
/// again; only threads racing to the first call make more than one, and every extra one
/// only counts the same fork twice.
pub(super) fn register_count_fork() {
    // SAFETY: `count_fork` is a function of this crate, which is never unloaded, and is
    // async-signal-safe, as a handler run in the child of a multithreaded `fork` must be.
    let registered = unsafe { pthread_atfork(None, None, Some(count_fork)) };
    if registered != 0 {
        // The only error is `ENOMEM` for the handler's entry: out of memory, as Rust
        // handles it everywhere else.
        alloc::handle_alloc_error(Layout::new::<[usize; 4]>());
    }
}

/// The child handler: one more fork, and forget what the parent's mappings left. The child
/// has one thread while it runs, and it only touches atomics.
extern "C" fn count_fork() {
    FORKS.fetch_add(1, Ordering::AcqRel);
    fork_generation::forget_inherited();
}

/// Forks counted so far.
pub(super) fn forks() -> u64 {
    FORKS.load(Ordering::Acquire)
}
