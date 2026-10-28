//! Write modes.

/// How a write treats an existing file.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PutMode {
    /// Create the file only if it does not exist, atomically: the compare-and-swap for roots,
    /// and the write of every other file a root commits to (FS-87).
    IfAbsent,
    /// Replace the file atomically if it exists. Only for share slots, which no root commits
    /// to. It gives no rollback protection: old copies may survive in backend versions.
    Replace,
}
