//! Why a key arena or plaintext buffer got less protection than the strongest level.

use std::fmt;

use crate::secure_mem::Level;
use crate::secure_mem::region::Refusal;

/// Why memory fell below the strongest level it may get, or got none: a key arena below the
/// strongest level of its [`Config`](crate::secure_mem::Config::with_strongest), as
/// [`Status::reason`](crate::secure_mem::Status::reason) reports it, or a plaintext buffer below
/// [`Level::Locked`], as [`Status::buffer_reason`](crate::secure_mem::Status::buffer_reason)
/// reports it.
///
/// Each names the refusal of the level just above the one the memory got, or of the last level
/// tried when it got none: memory that raising `RLIMIT_MEMLOCK` would lock is
/// [`LockLimit`](Fallback::LockLimit), even where `memfd_secret` is missing too.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Fallback {
    /// This build has no protected memory: a system other than Linux, or Miri. Keys and
    /// buffers are plain heap memory, wiped before it is freed.
    Platform,
    /// The system has no `memfd_secret(2)`: a kernel before 5.14, one where it is not enabled
    /// (off by default before 6.5, [commit b758fe6df50d]), or a seccomp filter that denies the
    /// call.
    ///
    /// [commit b758fe6df50d]: https://git.kernel.org/linus/b758fe6df50d
    SecretUnavailable,
    /// Locking the memory would pass `RLIMIT_MEMLOCK`, or the kernel refused to lock it.
    LockLimit,
    /// The kernel refused to map the memory or to apply its protections.
    KernelRefused,
}

impl Fallback {
    /// Why memory asked for at `asked`, which came back at `got`, is below the strongest level
    /// tried, given the refusal of the last stronger level; `None` if `asked` was the strongest
    /// and it got it.
    ///
    /// The cause is always the refusal of the level just above `got`, the one thing that stands
    /// between the memory and the next level up: memory below the level asked for means `mlock`
    /// failed or was over budget ([`Region::new`](crate::secure_mem::region::Region::new)
    /// downgrades only `Locked` to `DumpExcluded`), otherwise the level above it was refused
    /// outright. Refusals of levels further up (such as a missing `memfd_secret` under a lock
    /// limit) are not reported.
    pub(crate) fn cause(asked: Level, got: Level, last_refusal: Option<Refusal>) -> Option<Self> {
        if got < asked {
            Some(Fallback::LockLimit)
        } else {
            last_refusal.map(Refusal::fallback)
        }
    }

    /// The fallback stored in a byte, for atomics.
    pub(crate) const fn to_u8(self) -> u8 {
        match self {
            Fallback::Platform => 0,
            Fallback::SecretUnavailable => 1,
            Fallback::LockLimit => 2,
            Fallback::KernelRefused => 3,
        }
    }

    /// The inverse of [`to_u8`](Fallback::to_u8); `None` for any other byte.
    pub(crate) const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Fallback::Platform),
            1 => Some(Fallback::SecretUnavailable),
            2 => Some(Fallback::LockLimit),
            3 => Some(Fallback::KernelRefused),
            _ => None,
        }
    }
}

impl fmt::Display for Fallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Fallback::Platform => "no protected memory on this platform",
            Fallback::SecretUnavailable => "memfd_secret is not available",
            Fallback::LockLimit => "RLIMIT_MEMLOCK is too low",
            Fallback::KernelRefused => "the kernel refused the mapping",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_fallback_reads_as_its_cause() {
        assert_eq!(
            Fallback::Platform.to_string(),
            "no protected memory on this platform"
        );
        assert_eq!(
            Fallback::SecretUnavailable.to_string(),
            "memfd_secret is not available"
        );
        assert_eq!(Fallback::LockLimit.to_string(), "RLIMIT_MEMLOCK is too low");
        assert_eq!(
            Fallback::KernelRefused.to_string(),
            "the kernel refused the mapping"
        );
    }

    #[test]
    fn each_fallback_survives_its_byte() {
        for fallback in [
            Fallback::Platform,
            Fallback::SecretUnavailable,
            Fallback::LockLimit,
            Fallback::KernelRefused,
        ] {
            assert_eq!(Fallback::from_u8(fallback.to_u8()), Some(fallback));
        }
        assert_eq!(Fallback::from_u8(4), None);
        assert_eq!(Fallback::from_u8(u8::MAX), None, "the byte for none");
    }

    #[test]
    fn the_cause_is_the_refusal_of_the_level_just_above_the_one_got() {
        assert_eq!(
            Fallback::cause(
                Level::Locked,
                Level::DumpExcluded,
                Some(Refusal::Unsupported)
            ),
            Some(Fallback::LockLimit),
            "a lock refused after no memfd_secret is reported as the lock limit"
        );
        assert_eq!(
            Fallback::cause(Level::Locked, Level::DumpExcluded, None),
            Some(Fallback::LockLimit)
        );
        assert_eq!(
            Fallback::cause(Level::Locked, Level::Locked, Some(Refusal::Unsupported)),
            Some(Fallback::SecretUnavailable)
        );
        assert_eq!(
            Fallback::cause(Level::Locked, Level::Locked, Some(Refusal::LockLimit)),
            Some(Fallback::LockLimit)
        );
        assert_eq!(
            Fallback::cause(
                Level::DumpExcluded,
                Level::DumpExcluded,
                Some(Refusal::Kernel)
            ),
            Some(Fallback::KernelRefused)
        );
        assert_eq!(
            Fallback::cause(Level::Heap, Level::Heap, Some(Refusal::Platform)),
            Some(Fallback::Platform)
        );
        assert_eq!(Fallback::cause(Level::Secret, Level::Secret, None), None);
        assert_eq!(Fallback::cause(Level::Heap, Level::Heap, None), None);
    }
}
