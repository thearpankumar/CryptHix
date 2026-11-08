//! The generation a region, arena or pool belongs to, and the running process's.

#[cfg(all(target_os = "linux", not(miri)))]
use crate::secure_mem::fork_generation::marker;

/// The copy of the address space a region, arena or pool was made in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Generation(u64);

#[cfg(test)]
impl Generation {
    /// A generation other than `self`, as an ancestor's looks to a forked child.
    pub(crate) const fn of_another_process(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// The generation of the running process. In a child forked since the last call, the first
/// call clears the inherited lock budget, buffer level and reason (see the `fork_generation`
/// module docs).
pub(crate) fn current() -> Generation {
    #[cfg(all(target_os = "linux", not(miri)))]
    {
        Generation(marker::current())
    }
    #[cfg(not(all(target_os = "linux", not(miri))))]
    {
        Generation(1)
    }
}

/// Forgets what the parent's mappings charged and recorded. Only atomic stores, so it is safe in
/// a `pthread_atfork` child handler.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) fn forget_inherited() {
    crate::secure_mem::lock_budget::forget_inherited();
    crate::secure_mem::buffer_level::forget_inherited();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_os = "linux", not(miri)))]
    use crate::secure_mem::fork_generation::fork_handler;

    #[test]
    fn the_generation_holds_within_a_process() {
        let first = current();
        let on_another_thread = std::thread::spawn(current)
            .join()
            .expect("the thread returns");
        assert_eq!(first, on_another_thread);
        assert_eq!(first, current());
    }

    /// Runs `child` in a forked child, which reports whether it held by exiting 0.
    ///
    /// The child only reads and writes atomics and calls `_exit`, all async-signal-safe, so it
    /// is sound even though other test threads run in the parent.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[expect(unsafe_code, reason = "fork and _exit have no safe interface")]
    fn in_forked_child(child: impl FnOnce() -> bool) -> bool {
        // SAFETY: see above; the child ends in `_exit` without returning into the harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let held = child();
            // SAFETY: ends the child at once, without unwinding into the copied harness.
            unsafe { libc::_exit(i32::from(!held)) }
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above, writing only `status`.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert_eq!(waited, pid, "waitpid");
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    /// A child, and a child of that child, each run a generation of their own: none of their
    /// ancestors' regions counts as theirs. The marker page gives this whatever made the child.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn a_forked_child_and_its_own_child_each_get_a_new_generation() {
        let parent = current();
        assert!(in_forked_child(|| {
            let child = current();
            child != parent
                && current() == child
                && in_forked_child(|| {
                    let grandchild = current();
                    grandchild != parent && grandchild != child
                })
        }));
        assert_eq!(current(), parent, "the parent's generation is unchanged");
    }

    /// The fork handler of kernels without `MADV_WIPEONFORK` counts every `fork` in the child,
    /// so its generation moves on too.
    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn the_fork_handler_counts_each_fork_in_the_child() {
        fork_handler::register_count_fork();
        let before = fork_handler::forks();
        assert!(in_forked_child(|| fork_handler::forks() > before));
        assert_eq!(fork_handler::forks(), before, "only children count a fork");
    }
}
