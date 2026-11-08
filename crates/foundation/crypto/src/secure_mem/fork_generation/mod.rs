//! Which copy of the address space is running, so a child forked without `exec` knows which
//! regions, slots and pools it inherited.
//!
//! Every region, arena and pool records the [`Generation`] it was made in; it belongs to the
//! running process exactly when that is [`current`]. A process id would not do: a child made
//! with `CLONE_NEWPID` sees itself as pid 1, which its parent may also be in its own namespace,
//! a pid is reused once its process is reaped, and reading it is a system call on every key
//! access.
//!
//! On Linux the generation lives in a page marked `MADV_WIPEONFORK`, which the kernel hands to
//! every child as a zero page, whatever made it (`fork`, `_Fork`, a raw `clone` without
//! `CLONE_VM`); the setting stays on the page in the child, so its children see zero again
//! ([`madvise(2)`](https://man7.org/linux/man-pages/man2/madvise.2.html)). The first call that
//! finds the page zero gives the process the next generation, one above any its ancestors used.
//! This is how `BoringSSL` (`crypto/rand/fork_detect.cc`) and the kernel's vDSO `getrandom` (its
//! state is `VM_WIPEONFORK`, [LWN 974468](https://lwn.net/Articles/974468/)) detect a fork, and
//! it costs two atomic loads.
//!
//! Kernels before 4.14 have no `MADV_WIPEONFORK`. There a `pthread_atfork(3)` child handler
//! counts forks instead. It runs for `fork` but not for `_Fork` or a raw `clone`, which is why
//! `BoringSSL` does not trust it; it is still the best a kernel that old offers, and such a
//! child only trips over memory it should not use.
//!
//! A new generation also clears what the parent's mappings left behind, before anything can
//! read it: the lock budget's counts, and the buffer level and reason. None of the
//! parent's locked mappings exists in the child (`MADV_DONTFORK`, and `mlock` is not
//! inherited), so the child may lock all its own limit allows.
//!
//! Under Miri and on systems other than Linux the generation never changes. All memory there
//! is heap, so a forked child's copy of every key and buffer is its own copy-on-write memory,
//! which it may use and wipes when it drops it. Such a child is a copy of a process that may
//! have had other threads, so, as for any lock after `fork`, it should only `exec` if one of
//! them could have been making a key. Porting protected memory there (A11, A12) needs fork
//! detection too.

#[expect(
    clippy::module_inception,
    reason = "files are named after their main item"
)]
mod fork_generation;
#[cfg(all(target_os = "linux", not(miri)))]
mod fork_handler;
#[cfg(all(target_os = "linux", not(miri)))]
mod marker;

pub(crate) use fork_generation::{Generation, current};
