//! Runs a workload once per crash point and checks what a restart would find (M-44).

use std::error::Error;
use std::fmt;

use crypthix_types::backend::{Backend, BackendError};

use crate::fault::Fault;
use crate::fault_backend::FaultBackend;
use crate::memory_backend::MemoryBackend;
use crate::op::Op;

/// Where a run was crashed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CrashPoint {
    /// Operations that completed before the crash.
    pub after: u64,
    /// Operations the workload makes when nothing crashes.
    pub total: u64,
    /// The last operation that completed, if any.
    pub last: Option<Op>,
}

/// Why [`for_each_crash_point`] failed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CrashFailure {
    /// The workload failed without any fault, so there is nothing to crash.
    DryRun(BackendError),
    /// A crashed run did not repeat the dry run's operations up to the crash, so the workload
    /// is not deterministic and its crash points mean nothing.
    Nondeterministic {
        /// Where the run was crashed.
        point: CrashPoint,
    },
    /// The state left by a crash broke an invariant.
    Invariant {
        /// Where the run was crashed.
        point: CrashPoint,
        /// What the check reported.
        message: String,
    },
}

impl fmt::Display for CrashFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrashFailure::DryRun(error) => write!(f, "workload failed with no fault: {error}"),
            CrashFailure::Nondeterministic { point } => write!(
                f,
                "crash after {} of {} ops: the workload did not repeat its dry run",
                point.after, point.total
            ),
            CrashFailure::Invariant { point, message } => {
                write!(f, "crash after {} of {} ops", point.after, point.total)?;
                if let Some(op) = point.last {
                    write!(f, " (last: {:?} {:?})", op.kind, op.key)?;
                }
                write!(f, ": {message}")
            }
        }
    }
}

impl Error for CrashFailure {}

/// Crashes `workload` after every possible number of operations and checks each result.
///
/// The workload first runs once without faults to count its `N` operations. Then, for every
/// `k` in `0..=N`, it runs on a fresh store from `setup` with [`Fault::CrashAfter`]`(k)`; its
/// result is ignored, as a crashed process returns nothing. `check` receives the files that
/// survived, as a restarted process would find them, and returns an error message if an
/// invariant is broken. The workload must be deterministic.
///
/// Returns `N`.
///
/// # Errors
///
/// [`CrashFailure::DryRun`] if the workload fails without faults,
/// [`CrashFailure::Nondeterministic`] if a crashed run's operations before the crash differ
/// from the dry run's, or [`CrashFailure::Invariant`] for the first crash point whose check
/// fails.
pub fn for_each_crash_point<T>(
    setup: impl Fn() -> MemoryBackend,
    workload: impl Fn(&dyn Backend) -> Result<T, BackendError>,
    mut check: impl FnMut(CrashPoint, &MemoryBackend) -> Result<(), String>,
) -> Result<u64, CrashFailure> {
    let dry = FaultBackend::new(setup(), Fault::None);
    workload(&dry).map_err(CrashFailure::DryRun)?;
    let total = dry.ops();
    let log = dry.log();

    for after in 0..=total {
        let backend = FaultBackend::new(setup(), Fault::CrashAfter(after));
        // A crashed workload's result is meaningless; only the surviving files matter.
        let _ = workload(&backend);
        let last = after
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| log.get(index).copied());
        let point = CrashPoint { after, total, last };
        // The run must have made the same first `after` operations, and tried one more unless
        // the crash point is the end.
        let ran = backend.log();
        let prefix = usize::try_from(after).unwrap_or(usize::MAX);
        let reached = after == total || backend.ops() > after;
        if !reached || ran.get(..prefix) != log.get(..prefix) {
            return Err(CrashFailure::Nondeterministic { point });
        }
        let survivor = backend.into_inner();
        check(point, &survivor).map_err(|message| CrashFailure::Invariant { point, message })?;
    }
    Ok(total)
}
