//! Engine events.

use crate::backend::BackendError;
use crate::format_error::FormatError;
use crate::id::{Epoch, RootSeq, ShardId};

/// Something the engine reports to the guard, the log and the user interface.
///
/// Events carry IDs, counts and error kinds only, never secrets, plaintext or paths. Names
/// follow the genome-log kinds of format spec section 15 where one exists.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Event {
    /// A new vault root was committed.
    Commit {
        /// Sequence number of the new root.
        root_seq: RootSeq,
    },
    /// A commit lost the compare-and-swap on its root name and is retried on the newer root.
    CommitRetried {
        /// The sequence number that was taken.
        root_seq: RootSeq,
    },
    /// The read-back before a commit did not match the source (FS-88, M-45). A local fault,
    /// not tampering with stored data; the commit was aborted.
    ReadBackMismatch,
    /// A new key epoch was created and made active; the previous epoch starts draining.
    EpochCreate {
        /// The new epoch.
        epoch: Epoch,
    },
    /// A KEK rotation finished: nothing in the current root uses the old epoch (FS-90).
    Rotate {
        /// The epoch rotated away from.
        from: Epoch,
        /// The new active epoch.
        to: Epoch,
    },
    /// Stored data failed verification.
    VerifyFailed {
        /// What failed, for example `Rollback`, `Fork` or `ShardHash`.
        error: FormatError,
        /// The root being read, if known.
        root_seq: Option<RootSeq>,
        /// The shard involved, if known.
        shard: Option<ShardId>,
    },
    /// The device state is missing or invalid; the vault stays unmounted until the user
    /// re-trusts the newest root (FS-81).
    StateLost,
    /// The user re-trusted a root after [`Event::StateLost`], through a protected action.
    ReTrusted {
        /// The root that is trusted now.
        root_seq: RootSeq,
    },
    /// A garbage-collection sweep finished (FS-91).
    GcSweep {
        /// Shards deleted.
        deleted: u64,
        /// Shards kept because a retention lock refused the delete.
        locked: u64,
    },
    /// A store listing found names of a known shape that are not canonical (FS-92).
    NonCanonicalNames {
        /// How many were found.
        count: u64,
    },
    /// A backend operation failed.
    BackendFailed {
        /// What failed.
        error: BackendError,
    },
}
