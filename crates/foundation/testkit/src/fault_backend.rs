//! A backend wrapper that injects faults.

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use crypthix_types::backend::{Backend, BackendError, ByteRange, Capabilities, DeleteOutcome};
use crypthix_types::backend::{ListEntry, ObjectMeta, PutMode, PutOutcome, ReadMode};
use crypthix_types::store_key::{StoreKey, StorePrefix};

use crate::fault::Fault;
use crate::op::{Op, OpKind};

/// Wraps a backend, records every operation and injects one [`Fault`].
///
/// # Examples
///
/// ```
/// use crypthix_testkit::{Fault, FaultBackend, MemoryBackend};
/// use crypthix_types::backend::{Backend, BackendError, PutMode, PutOutcome};
/// use crypthix_types::id::RootSeq;
/// use crypthix_types::store_key::StoreKey;
///
/// let backend = FaultBackend::new(MemoryBackend::new(), Fault::CrashAfter(1));
/// let first = StoreKey::Root(RootSeq::FIRST);
/// let second = StoreKey::Root(RootSeq::FIRST.checked_next().expect("not the maximum"));
/// assert_eq!(backend.put(&first, b"a", PutMode::IfAbsent), Ok(PutOutcome::Created));
/// assert_eq!(backend.put(&second, b"b", PutMode::IfAbsent), Err(BackendError::Unavailable));
/// assert!(backend.crashed());
/// assert_eq!(backend.into_inner().files().len(), 1);
/// ```
#[derive(Debug)]
pub struct FaultBackend<B> {
    inner: B,
    fault: Fault,
    log: Mutex<Vec<Op>>,
    /// Whether the fault changed the outcome of an operation.
    applied: AtomicBool,
}

/// What to do with the operation that is about to run.
enum Step {
    Run,
    Fail(BackendError),
    LoseReply,
    Corrupt,
}

impl<B: Backend> FaultBackend<B> {
    /// Wraps `inner`, injecting `fault`.
    #[must_use]
    pub fn new(inner: B, fault: Fault) -> Self {
        Self {
            inner,
            fault,
            log: Mutex::new(Vec::new()),
            applied: AtomicBool::new(false),
        }
    }

    /// Every operation called so far, including those that failed.
    #[must_use]
    pub fn log(&self) -> Vec<Op> {
        self.lock().clone()
    }

    /// The number of operations called so far.
    #[must_use]
    pub fn ops(&self) -> u64 {
        u64::try_from(self.lock().len()).unwrap_or(u64::MAX)
    }

    /// Whether the fault took effect: an operation failed, lost its reply or returned flipped
    /// bytes. A test that expects a fault should assert this, so a fault placed on the wrong
    /// operation (say, a corruption on a write) cannot pass unnoticed.
    #[must_use]
    pub fn applied(&self) -> bool {
        self.applied.load(Ordering::Relaxed)
    }

    /// Whether a [`Fault::CrashAfter`] has been reached.
    #[must_use]
    pub fn crashed(&self) -> bool {
        matches!(self.fault, Fault::CrashAfter(n) if self.ops() > n)
    }

    /// The wrapped backend, holding exactly the writes that completed.
    #[must_use]
    pub fn into_inner(self) -> B {
        self.inner
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Op>> {
        self.log
            .lock()
            .expect("a test thread panicked while holding the log")
    }

    /// Records the operation and decides its fate.
    fn begin(&self, kind: OpKind, key: Option<&StoreKey>) -> Step {
        let mut log = self.lock();
        let index = u64::try_from(log.len()).unwrap_or(u64::MAX);
        log.push(Op {
            kind,
            key: key.copied(),
        });
        match self.fault {
            Fault::CrashAfter(n) if index >= n => Step::Fail(BackendError::Unavailable),
            Fault::ErrorAt(n, error) if index == n => Step::Fail(error),
            Fault::LostReplyAt(n) if index == n => Step::LoseReply,
            Fault::CorruptUncachedReadAt(n) if index == n => Step::Corrupt,
            _ => Step::Run,
        }
    }

    /// Runs one operation under the fault plan.
    fn run<T>(
        &self,
        kind: OpKind,
        key: Option<&StoreKey>,
        op: impl FnOnce() -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        match self.begin(kind, key) {
            // Corruption applies to uncached reads only; see `get`.
            Step::Run | Step::Corrupt => op(),
            Step::Fail(error) => self.fail(error),
            Step::LoseReply => {
                let _ = op()?;
                self.fail(BackendError::Unavailable)
            }
        }
    }

    fn fail<T>(&self, error: BackendError) -> Result<T, BackendError> {
        self.applied.store(true, Ordering::Relaxed);
        Err(error)
    }
}

impl<B: Backend> Backend for FaultBackend<B> {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn get(
        &self,
        key: &StoreKey,
        range: ByteRange,
        read: ReadMode,
    ) -> Result<Vec<u8>, BackendError> {
        match self.begin(OpKind::Get, Some(key)) {
            Step::Run => self.inner.get(key, range, read),
            Step::Fail(error) => self.fail(error),
            Step::LoseReply => {
                let _ = self.inner.get(key, range, read)?;
                self.fail(BackendError::Unavailable)
            }
            Step::Corrupt => {
                let mut bytes = self.inner.get(key, range, read)?;
                if read == ReadMode::Uncached
                    && let Some(first) = bytes.first_mut()
                {
                    *first ^= 1;
                    self.applied.store(true, Ordering::Relaxed);
                }
                Ok(bytes)
            }
        }
    }

    fn stat(&self, key: &StoreKey) -> Result<Option<ObjectMeta>, BackendError> {
        self.run(OpKind::Stat, Some(key), || self.inner.stat(key))
    }

    fn put(&self, key: &StoreKey, bytes: &[u8], mode: PutMode) -> Result<PutOutcome, BackendError> {
        self.run(OpKind::Put, Some(key), || self.inner.put(key, bytes, mode))
    }

    fn list(
        &self,
        prefix: StorePrefix,
        visit: &mut dyn FnMut(ListEntry) -> ControlFlow<()>,
    ) -> Result<(), BackendError> {
        self.run(OpKind::List(prefix), None, || {
            self.inner.list(prefix, visit)
        })
    }

    fn delete(&self, key: &StoreKey) -> Result<DeleteOutcome, BackendError> {
        self.run(OpKind::Delete, Some(key), || self.inner.delete(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_backend::MemoryBackend;
    use crypthix_types::id::RootSeq;

    fn root(n: u64) -> StoreKey {
        let mut seq = RootSeq::FIRST;
        for _ in 1..n {
            seq = seq.checked_next().expect("small");
        }
        StoreKey::Root(seq)
    }

    fn whole(key: &StoreKey) -> ByteRange {
        ByteRange::prefix(key.max_file_len())
    }

    #[test]
    fn crash_after_zero_runs_nothing() {
        let backend = FaultBackend::new(MemoryBackend::new(), Fault::CrashAfter(0));
        assert_eq!(
            backend.put(&root(1), b"a", PutMode::IfAbsent),
            Err(BackendError::Unavailable)
        );
        assert!(backend.crashed(), "the first operation is past the crash");
        assert!(
            backend.into_inner().files().is_empty(),
            "nothing ran before the crash"
        );
    }

    #[test]
    fn error_at_fails_once_without_effect() {
        let fault = Fault::ErrorAt(0, BackendError::RateLimited);
        let backend = FaultBackend::new(MemoryBackend::new(), fault);
        assert_eq!(
            backend.put(&root(1), b"a", PutMode::IfAbsent),
            Err(BackendError::RateLimited)
        );
        assert_eq!(backend.stat(&root(1)), Ok(None));
        assert_eq!(
            backend.put(&root(1), b"a", PutMode::IfAbsent),
            Ok(PutOutcome::Created)
        );
        assert!(!backend.crashed(), "an injected error is not a crash");
        assert!(backend.applied(), "the error was injected");
        assert_eq!(backend.ops(), 3);
    }

    #[test]
    fn lost_reply_keeps_the_write() {
        let backend = FaultBackend::new(MemoryBackend::new(), Fault::LostReplyAt(0));
        assert_eq!(
            backend.put(&root(1), b"a", PutMode::IfAbsent),
            Err(BackendError::Unavailable)
        );
        assert_eq!(
            backend.put(&root(1), b"a", PutMode::IfAbsent),
            Ok(PutOutcome::AlreadyExists)
        );
    }

    #[test]
    fn corruption_hits_uncached_reads_only() {
        let inner = MemoryBackend::new();
        assert_eq!(
            inner.put(&root(1), b"abc", PutMode::IfAbsent),
            Ok(PutOutcome::Created)
        );
        let backend = FaultBackend::new(inner.clone(), Fault::CorruptUncachedReadAt(0));
        assert_eq!(
            backend.get(&root(1), whole(&root(1)), ReadMode::Uncached),
            Ok(b"`bc".to_vec())
        );
        let backend = FaultBackend::new(inner, Fault::CorruptUncachedReadAt(0));
        assert_eq!(
            backend.get(&root(1), whole(&root(1)), ReadMode::Cached),
            Ok(b"abc".to_vec())
        );
        assert!(!backend.applied(), "a cached read is left alone");
    }

    #[test]
    fn records_every_operation() {
        let backend = FaultBackend::new(MemoryBackend::new(), Fault::None);
        let _ = backend.capabilities();
        let _ = backend.stat(&root(1));
        let _ = backend.list(StorePrefix::Roots, &mut |_| ControlFlow::Continue(()));
        let _ = backend.delete(&root(2));
        assert_eq!(
            backend.log(),
            [
                Op {
                    kind: OpKind::Stat,
                    key: Some(root(1))
                },
                Op {
                    kind: OpKind::List(StorePrefix::Roots),
                    key: None
                },
                Op {
                    kind: OpKind::Delete,
                    key: Some(root(2))
                },
            ]
        );
    }
}
