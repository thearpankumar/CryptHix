//! Write outcomes.

/// The result of a successful [`put`](crate::backend::Backend::put).
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PutOutcome {
    /// The file was written.
    Created,
    /// With [`PutMode::IfAbsent`](crate::backend::PutMode::IfAbsent): a file already exists
    /// under the name and was left unchanged.
    ///
    /// This does not prove that another writer won. A retried request whose first attempt
    /// succeeded also ends here, and a hostile backend may have planted the file. The caller
    /// MUST read the file back and compare it: a root with the caller's own hash is a success;
    /// a shard goes through the read-back check of FS-88 like a new one.
    AlreadyExists,
}
