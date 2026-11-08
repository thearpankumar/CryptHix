//! How well a piece of secret memory is protected.

use std::fmt;

/// The protection a mapping of secret memory got, weakest first, so levels compare with `<`.
///
/// Every level is wiped before it is freed.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Level {
    /// Ordinary heap memory. Plaintext buffers get it only where the others do not exist:
    /// under Miri and on systems other than Linux. On Linux a key gets it only from a pool
    /// whose minimum is `Heap`.
    Heap,
    /// A private anonymous mapping left out of core dumps (`MADV_DONTDUMP`) and of forked
    /// children (`MADV_DONTFORK`), but not locked: `mlock` failed or would pass
    /// `RLIMIT_MEMLOCK`, so its pages can be swapped.
    DumpExcluded,
    /// [`DumpExcluded`](Level::DumpExcluded) and locked in RAM with `mlock`, so it is never
    /// swapped. Hibernation still writes it to disk.
    Locked,
    /// A `memfd_secret(2)` mapping: removed from the kernel's direct map, never swapped, left out
    /// of core dumps, and unreadable through `PTRACE_PEEKDATA`, `process_vm_readv` and
    /// `/proc/<pid>/mem`, all of which reach memory through `get_user_pages`, which refuses
    /// these pages (`check_vma_flags` in `mm/gup.c`; the kernel's `memfd_secret` selftest checks
    /// the first two). A process allowed to `ptrace` this one can still inject code that reads
    /// them, so it does not replace stopping tracers. Linux 5.14 and later, on by default since
    /// 6.5 ([commit b758fe6df50d](https://git.kernel.org/linus/b758fe6df50d)). Used for keys
    /// only (see [`secure_mem`](crate::secure_mem#why-plaintext-stays-out-of-secret-memory)):
    /// as long as one exists, the process cannot be hibernated.
    Secret,
}

impl Level {
    /// The weakest level this build can give a key: [`DumpExcluded`](Level::DumpExcluded) on
    /// Linux, [`Heap`](Level::Heap) under Miri and elsewhere.
    #[must_use]
    pub const fn platform_floor() -> Self {
        if cfg!(all(target_os = "linux", not(miri))) {
            Level::DumpExcluded
        } else {
            Level::Heap
        }
    }

    /// The level as a short lowercase name, as `crypthix status` shows it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Level::Heap => "heap",
            Level::DumpExcluded => "dump-excluded",
            Level::Locked => "locked",
            Level::Secret => "secret",
        }
    }

    /// The level stored in a byte, for atomics.
    pub(crate) const fn to_u8(self) -> u8 {
        match self {
            Level::Heap => 0,
            Level::DumpExcluded => 1,
            Level::Locked => 2,
            Level::Secret => 3,
        }
    }

    /// The inverse of [`to_u8`](Level::to_u8); `None` for any other byte.
    pub(crate) const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Level::Heap),
            1 => Some(Level::DumpExcluded),
            2 => Some(Level::Locked),
            3 => Some(Level::Secret),
            _ => None,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Level; 4] = [
        Level::Heap,
        Level::DumpExcluded,
        Level::Locked,
        Level::Secret,
    ];

    #[test]
    fn levels_order_weakest_first() {
        assert!(ALL.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn byte_form_round_trips() {
        for level in ALL {
            assert_eq!(Level::from_u8(level.to_u8()), Some(level));
        }
        assert_eq!(Level::from_u8(4), None);
    }

    #[test]
    fn names_are_distinct() {
        let names: std::collections::BTreeSet<_> = ALL.iter().map(|level| level.as_str()).collect();
        assert_eq!(names.len(), ALL.len());
    }
}
