//! Why a mapping at one level failed.

use crate::secure_mem::Fallback;

/// Why a mapping at one level failed, so the caller can try the next level and report why.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Refusal {
    /// This build has no protected memory at all: a system other than Linux, or Miri.
    #[cfg_attr(
        all(target_os = "linux", not(miri), not(test)),
        expect(dead_code, reason = "Linux maps every level but the heap")
    )]
    Platform,
    /// The system has no `memfd_secret`.
    #[cfg_attr(
        not(any(test, all(target_os = "linux", not(miri)))),
        expect(dead_code, reason = "only Linux has memfd_secret")
    )]
    Unsupported,
    /// The mapping would pass `RLIMIT_MEMLOCK`.
    #[cfg_attr(
        not(any(test, all(target_os = "linux", not(miri)))),
        expect(dead_code, reason = "only Linux locks memory")
    )]
    LockLimit,
    /// The kernel refused the mapping or its advice.
    Kernel,
}

impl Refusal {
    /// The cause [`Status::reason`](crate::secure_mem::Status::reason) reports.
    pub(crate) const fn fallback(self) -> Fallback {
        match self {
            Refusal::Platform => Fallback::Platform,
            Refusal::Unsupported => Fallback::SecretUnavailable,
            Refusal::LockLimit => Fallback::LockLimit,
            Refusal::Kernel => Fallback::KernelRefused,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_refusal_reports_its_own_cause() {
        assert_eq!(Refusal::Platform.fallback(), Fallback::Platform);
        assert_eq!(Refusal::Unsupported.fallback(), Fallback::SecretUnavailable);
        assert_eq!(Refusal::LockLimit.fallback(), Fallback::LockLimit);
        assert_eq!(Refusal::Kernel.fallback(), Fallback::KernelRefused);
    }
}
