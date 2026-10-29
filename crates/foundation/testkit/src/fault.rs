//! Faults that [`FaultBackend`](crate::FaultBackend) injects.

use crypthix_types::backend::BackendError;

/// A fault, placed by the index of a backend operation (the first operation is 0).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Fault {
    /// No fault.
    #[default]
    None,
    /// The process dies after `n` operations: the first `n` complete, and every later one
    /// fails with [`BackendError::Unavailable`] without touching the store. `CrashAfter(0)`
    /// crashes before the first operation.
    CrashAfter(u64),
    /// Operation `n` fails with the error and has no effect; later operations succeed.
    ErrorAt(u64, BackendError),
    /// Operation `n` takes effect, but its reply is lost: the caller sees
    /// [`BackendError::Unavailable`]. Models a timeout after a successful write.
    LostReplyAt(u64),
    /// If operation `n` is an uncached read, one bit of its result is flipped: corruption on
    /// the way to the disk that the read-back check must catch (FS-88, M-45).
    CorruptUncachedReadAt(u64),
}
