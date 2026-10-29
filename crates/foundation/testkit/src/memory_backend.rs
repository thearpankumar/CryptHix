//! An in-memory backend.

use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::{Mutex, MutexGuard};

use crypthix_types::backend::{Backend, BackendError, ByteRange, Capabilities, DeleteOutcome};
use crypthix_types::backend::{ListEntry, ObjectMeta, PutMode, PutOutcome, ReadMode};
use crypthix_types::store_key::{StoreKey, StorePrefix};

/// A backend that keeps files in memory.
///
/// Every write is durable the moment it returns, as the [`Backend`] contract requires, so the
/// files left after a crash are exactly the writes that completed. Cloning copies the files.
#[derive(Debug)]
pub struct MemoryBackend {
    files: Mutex<BTreeMap<StoreKey, Vec<u8>>>,
    capabilities: Capabilities,
}

impl MemoryBackend {
    /// What an in-memory backend can do: atomic create, uncached and ranged reads.
    pub const CAPABILITIES: Capabilities = Capabilities::ATOMIC_CREATE
        .union(Capabilities::UNCACHED_READ)
        .union(Capabilities::RANGED_GET);

    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::from_files(BTreeMap::new())
    }

    /// A store holding `files`.
    #[must_use]
    pub fn from_files(files: BTreeMap<StoreKey, Vec<u8>>) -> Self {
        Self {
            files: Mutex::new(files),
            capabilities: Self::CAPABILITIES,
        }
    }

    /// The same store, declaring `capabilities` instead, to test how callers handle a weaker
    /// backend.
    #[must_use]
    pub fn with_capabilities(self, capabilities: Capabilities) -> Self {
        Self {
            capabilities,
            ..self
        }
    }

    /// A copy of every file.
    #[must_use]
    pub fn files(&self) -> BTreeMap<StoreKey, Vec<u8>> {
        self.lock().clone()
    }

    /// The contents of one file.
    #[must_use]
    pub fn file(&self, key: &StoreKey) -> Option<Vec<u8>> {
        self.lock().get(key).cloned()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<StoreKey, Vec<u8>>> {
        self.files
            .lock()
            .expect("a test thread panicked while holding the store")
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MemoryBackend {
    fn clone(&self) -> Self {
        Self::from_files(self.files()).with_capabilities(self.capabilities)
    }
}

fn meta(file: &[u8]) -> Result<ObjectMeta, BackendError> {
    let len = u64::try_from(file.len()).map_err(|_| BackendError::InvalidResponse)?;
    Ok(ObjectMeta::new(len))
}

impl Backend for MemoryBackend {
    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    fn get(
        &self,
        key: &StoreKey,
        range: ByteRange,
        _read: ReadMode,
    ) -> Result<Vec<u8>, BackendError> {
        let files = self.lock();
        let file = files.get(key).ok_or(BackendError::NotFound)?;
        let start = usize::try_from(range.start()).unwrap_or(usize::MAX);
        let len = usize::try_from(range.len()).unwrap_or(usize::MAX);
        let bytes: Vec<u8> = file.iter().skip(start).take(len).copied().collect();
        range.check_response(&bytes)?;
        Ok(bytes)
    }

    fn stat(&self, key: &StoreKey) -> Result<Option<ObjectMeta>, BackendError> {
        self.lock().get(key).map(|file| meta(file)).transpose()
    }

    fn put(&self, key: &StoreKey, bytes: &[u8], mode: PutMode) -> Result<PutOutcome, BackendError> {
        let mut files = self.lock();
        if mode == PutMode::IfAbsent && files.contains_key(key) {
            return Ok(PutOutcome::AlreadyExists);
        }
        files.insert(*key, bytes.to_vec());
        Ok(PutOutcome::Created)
    }

    fn list(
        &self,
        prefix: StorePrefix,
        visit: &mut dyn FnMut(ListEntry) -> ControlFlow<()>,
    ) -> Result<(), BackendError> {
        // Copy first, so `visit` may call back into the backend.
        let files = self.files();
        for (key, file) in &files {
            if !prefix.contains(key) {
                continue;
            }
            let entry = ListEntry::File {
                key: *key,
                meta: meta(file)?,
            };
            if visit(entry).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn delete(&self, key: &StoreKey) -> Result<DeleteOutcome, BackendError> {
        Ok(match self.lock().remove(key) {
            Some(_) => DeleteOutcome::Deleted,
            None => DeleteOutcome::NotFound,
        })
    }
}
