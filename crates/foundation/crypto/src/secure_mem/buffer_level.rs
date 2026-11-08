//! The weakest level any plaintext buffer got, and why the latest one fell below
//! [`Level::Locked`], for [`status`](fn@crate::secure_mem::status).

use std::sync::atomic::{AtomicU8, Ordering};

use crate::secure_mem::{Fallback, Level};

/// The byte that stands for no level or reason yet, which neither encoding uses.
const NONE: u8 = u8::MAX;

/// The weakest level so far; [`NONE`] until the first buffer.
static WEAKEST: AtomicU8 = AtomicU8::new(NONE);

/// Why the latest buffer fell below `Locked` or got no memory; [`NONE`] until one did.
static REASON: AtomicU8 = AtomicU8::new(NONE);

/// Records the level of a new buffer, and why it is below `Locked` if it is.
pub(crate) fn record(level: Level, reason: Option<Fallback>) {
    record_in(&WEAKEST, level);
    if let Some(reason) = reason {
        record_reason_in(&REASON, reason);
    }
}

/// Records why a buffer could not be mapped at any level.
pub(crate) fn record_refusal(reason: Fallback) {
    record_reason_in(&REASON, reason);
}

/// The weakest level so far.
pub(crate) fn weakest() -> Option<Level> {
    weakest_in(&WEAKEST)
}

/// Why the latest buffer below `Locked`, or refused, was.
pub(crate) fn reason() -> Option<Fallback> {
    reason_in(&REASON)
}

/// Forgets the levels and reason a forked child's parent recorded, when the child takes its
/// generation (see `fork_generation`): those buffers are not mapped in the child. Atomic stores,
/// so a `pthread_atfork` child handler may call it.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn forget_inherited() {
    WEAKEST.store(NONE, Ordering::Release);
    REASON.store(NONE, Ordering::Release);
}

/// Lowers `weakest` to `level` if that is weaker than what it holds.
fn record_in(weakest: &AtomicU8, level: Level) {
    weakest.fetch_min(level.to_u8(), Ordering::AcqRel);
}

/// The level `weakest` holds; `None` before the first [`record_in`].
fn weakest_in(weakest: &AtomicU8) -> Option<Level> {
    Level::from_u8(weakest.load(Ordering::Acquire))
}

/// Makes `reason` the latest in `latest`.
fn record_reason_in(latest: &AtomicU8, reason: Fallback) {
    latest.store(reason.to_u8(), Ordering::Release);
}

/// The reason `latest` holds; `None` before the first [`record_reason_in`].
fn reason_in(latest: &AtomicU8) -> Option<Fallback> {
    Fallback::from_u8(latest.load(Ordering::Acquire))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a counter of its own: the process-wide one is what `status` reports to other tests.
    #[test]
    fn recording_keeps_the_weakest() {
        let weakest = AtomicU8::new(NONE);
        assert_eq!(weakest_in(&weakest), None, "nothing recorded yet");
        record_in(&weakest, Level::Locked);
        assert_eq!(weakest_in(&weakest), Some(Level::Locked));
        record_in(&weakest, Level::Secret);
        assert_eq!(
            weakest_in(&weakest),
            Some(Level::Locked),
            "a stronger level does not raise it"
        );
        record_in(&weakest, Level::DumpExcluded);
        assert_eq!(weakest_in(&weakest), Some(Level::DumpExcluded));
    }

    /// On a byte of its own, as above.
    #[test]
    fn the_latest_reason_is_kept() {
        let latest = AtomicU8::new(NONE);
        assert_eq!(reason_in(&latest), None, "nothing recorded yet");
        record_reason_in(&latest, Fallback::LockLimit);
        assert_eq!(reason_in(&latest), Some(Fallback::LockLimit));
        record_reason_in(&latest, Fallback::KernelRefused);
        assert_eq!(
            reason_in(&latest),
            Some(Fallback::KernelRefused),
            "the latest, not the first"
        );
    }
}
