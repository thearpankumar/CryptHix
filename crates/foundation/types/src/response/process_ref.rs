//! A reference to one process that survives PID reuse.

use std::num::NonZeroU32;

/// A process, named by its PID and its start time so a reused PID never matches (M-3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ProcessRef {
    pid: NonZeroU32,
    start_time: u64,
}

impl ProcessRef {
    /// A process with `pid` that started at `start_time`, in clock ticks since boot as in
    /// `/proc/<pid>/stat`.
    #[must_use]
    pub const fn new(pid: NonZeroU32, start_time: u64) -> Self {
        Self { pid, start_time }
    }

    /// The process ID.
    #[must_use]
    pub const fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    /// The start time in clock ticks since boot.
    #[must_use]
    pub const fn start_time(&self) -> u64 {
        self.start_time
    }
}
