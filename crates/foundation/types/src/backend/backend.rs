//! The storage backend trait.

use std::ops::ControlFlow;

use crate::backend::ObjectMeta;
use crate::backend::{BackendError, ByteRange, Capabilities, DeleteOutcome, ListEntry};
use crate::backend::{PutMode, PutOutcome, ReadMode};
use crate::store_key::{StoreKey, StorePrefix};

/// A store that holds the files of one vault: the local `store/` folder in Phase 1, cloud
/// providers from Phase 4.
///
/// A backend is untrusted (format spec section 2): it may read, change, drop or replay every
/// byte. Callers verify everything they read. The trait is synchronous and object-safe, so the
/// daemon can hold a `Box<dyn Backend>`; remote backends run it on a blocking thread.
pub trait Backend: Send + Sync {
    /// What this backend declares. `init` refuses a store without
    /// [`Capabilities::ATOMIC_CREATE`] and probes the store itself as well (FS-87).
    fn capabilities(&self) -> Capabilities;

    /// Reads at most `range.len()` bytes of a file starting at `range.start()`. Fewer bytes
    /// mean the file ended.
    ///
    /// [`ReadMode::Uncached`] must bypass every cache between the caller and the medium, for
    /// the read-back check before a commit (FS-88, M-45). The result must pass
    /// [`ByteRange::check_response`]. Store files are opened without following symlinks
    /// (FS-92); anything but a regular file is [`BackendError::NotRegularFile`].
    ///
    /// # Errors
    ///
    /// [`BackendError::NotFound`] if the file does not exist, or another backend error.
    fn get(
        &self,
        key: &StoreKey,
        range: ByteRange,
        read: ReadMode,
    ) -> Result<Vec<u8>, BackendError>;

    /// The size of a file, or `None` if it does not exist.
    ///
    /// # Errors
    ///
    /// A backend error.
    fn stat(&self, key: &StoreKey) -> Result<Option<ObjectMeta>, BackendError>;

    /// Writes a whole file durably.
    ///
    /// With [`PutMode::IfAbsent`] the write is atomic and never replaces an existing file; on
    /// `roots/<seq>` this is the compare-and-swap of FS-87 (M-44). A crash leaves either no
    /// file or the complete file, never a partial one. See [`PutOutcome::AlreadyExists`] for
    /// what the caller must check.
    ///
    /// # Errors
    ///
    /// [`BackendError::Unsupported`] if the mode is not supported, or another backend error.
    fn put(&self, key: &StoreKey, bytes: &[u8], mode: PutMode) -> Result<PutOutcome, BackendError>;

    /// Calls `visit` for every file under `prefix`, in no particular order, until it returns
    /// [`ControlFlow::Break`]. Names that fit no pattern are skipped; names of a known shape
    /// that are not canonical are reported as [`ListEntry::NonCanonical`] (FS-92). `visit`
    /// must not call back into the backend.
    ///
    /// # Errors
    ///
    /// A backend error.
    fn list(
        &self,
        prefix: StorePrefix,
        visit: &mut dyn FnMut(ListEntry) -> ControlFlow<()>,
    ) -> Result<(), BackendError>;

    /// Deletes a file. A refusal because of a retention lock is
    /// [`DeleteOutcome::Locked`], not an error (FS-91).
    ///
    /// # Errors
    ///
    /// A backend error.
    fn delete(&self, key: &StoreKey) -> Result<DeleteOutcome, BackendError>;
}
