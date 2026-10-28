//! Delete outcomes.

/// The result of a successful [`delete`](crate::backend::Backend::delete).
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DeleteOutcome {
    /// The name is no longer listed. The bytes may survive in backend versions or retention,
    /// which counts toward the deletion horizon (FS-91).
    Deleted,
    /// The file did not exist, where the backend can tell.
    NotFound,
    /// A retention lock refused the delete; the file stays until the lock expires (FS-91).
    Locked,
}
