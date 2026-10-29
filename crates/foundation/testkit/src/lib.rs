//! Test support for CryptHix crates: an in-memory [`Backend`](crypthix_types::backend::Backend),
//! fault injection and a driver that crashes a workload at every step (M-44).
//!
//! This crate is a dev-dependency only; `cargo xtask check-layers` rejects it as a normal or
//! build dependency, so test doubles never reach a shipped binary.

mod crash_points;
mod fault;
mod fault_backend;
mod memory_backend;
mod op;

pub use crash_points::{CrashFailure, CrashPoint, for_each_crash_point};
pub use fault::Fault;
pub use fault_backend::FaultBackend;
pub use memory_backend::MemoryBackend;
pub use op::{Op, OpKind};
