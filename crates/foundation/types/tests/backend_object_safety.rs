//! `Backend` is usable as a trait object, and its outcomes describe compare-and-swap.

use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::Mutex;

use crypthix_types::backend::{Backend, BackendError, ByteRange, Capabilities, DeleteOutcome};
use crypthix_types::backend::{ListEntry, ObjectMeta, PutMode, PutOutcome, ReadMode};
use crypthix_types::id::{ConfigSeq, RootSeq};
use crypthix_types::store_key::{StoreKey, StorePrefix};

/// An in-memory backend, for this test only.
#[derive(Default)]
struct MemoryBackend {
    files: Mutex<BTreeMap<StoreKey, Vec<u8>>>,
}

impl Backend for MemoryBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities::ATOMIC_CREATE
    }

    fn get(
        &self,
        key: &StoreKey,
        range: ByteRange,
        _read: ReadMode,
    ) -> Result<Vec<u8>, BackendError> {
        let files = self.files.lock().expect("not poisoned");
        let file = files.get(key).ok_or(BackendError::NotFound)?;
        let start = usize::try_from(range.start()).map_err(|_| BackendError::Unsupported)?;
        let len = usize::try_from(range.len()).map_err(|_| BackendError::Unsupported)?;
        let bytes: Vec<u8> = file.iter().skip(start).take(len).copied().collect();
        range.check_response(&bytes)?;
        Ok(bytes)
    }

    fn stat(&self, key: &StoreKey) -> Result<Option<ObjectMeta>, BackendError> {
        let files = self.files.lock().expect("not poisoned");
        Ok(files
            .get(key)
            .map(|file| ObjectMeta::new(file.len() as u64)))
    }

    fn put(&self, key: &StoreKey, bytes: &[u8], mode: PutMode) -> Result<PutOutcome, BackendError> {
        let mut files = self.files.lock().expect("not poisoned");
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
        let files = self.files.lock().expect("not poisoned");
        for (key, file) in files.iter() {
            let entry = ListEntry::File {
                key: *key,
                meta: ObjectMeta::new(file.len() as u64),
            };
            if prefix.contains(key) && visit(entry).is_break() {
                break;
            }
        }
        Ok(())
    }

    fn delete(&self, key: &StoreKey) -> Result<DeleteOutcome, BackendError> {
        let mut files = self.files.lock().expect("not poisoned");
        Ok(match files.remove(key) {
            Some(_) => DeleteOutcome::Deleted,
            None => DeleteOutcome::NotFound,
        })
    }
}

#[test]
fn root_put_is_a_compare_and_swap() {
    let backend: Box<dyn Backend> = Box::new(MemoryBackend::default());
    assert!(
        backend.capabilities().contains(Capabilities::ATOMIC_CREATE),
        "a backend that holds roots declares atomic create"
    );
    let root = StoreKey::Root(RootSeq::FIRST);
    let whole = ByteRange::prefix(root.max_file_len());
    assert_eq!(
        backend.put(&root, b"first", PutMode::IfAbsent),
        Ok(PutOutcome::Created)
    );
    assert_eq!(
        backend.put(&root, b"racing", PutMode::IfAbsent),
        Ok(PutOutcome::AlreadyExists)
    );
    assert_eq!(
        backend.get(&root, whole, ReadMode::Uncached).as_deref(),
        Ok(&b"first"[..])
    );
    let middle = ByteRange::new(1, 2).expect("in range");
    assert_eq!(
        backend.get(&root, middle, ReadMode::Cached).as_deref(),
        Ok(&b"ir"[..])
    );
}

#[test]
fn already_exists_after_a_retried_success_is_resolved_by_reading_back() {
    let backend = MemoryBackend::default();
    let root = StoreKey::Root(RootSeq::FIRST);
    let ours = b"our root";
    // The first attempt succeeded but its answer was lost; the retry sees the name taken.
    assert_eq!(
        backend.put(&root, ours, PutMode::IfAbsent),
        Ok(PutOutcome::Created)
    );
    assert_eq!(
        backend.put(&root, ours, PutMode::IfAbsent),
        Ok(PutOutcome::AlreadyExists)
    );
    let stored = backend
        .get(
            &root,
            ByteRange::prefix(root.max_file_len()),
            ReadMode::Uncached,
        )
        .expect("readable");
    assert_eq!(
        stored, ours,
        "the caller compares and finds its own root: a success"
    );
}

#[test]
fn list_and_delete() {
    let backend: &dyn Backend = &MemoryBackend::default();
    let first = StoreKey::Root(RootSeq::FIRST);
    let second = StoreKey::Root(RootSeq::FIRST.checked_next().expect("not at the maximum"));
    for key in [first, second, StoreKey::Config(ConfigSeq::FIRST)] {
        assert_eq!(
            backend.put(&key, b"x", PutMode::IfAbsent),
            Ok(PutOutcome::Created)
        );
    }
    let mut roots: Vec<StoreKey> = Vec::new();
    backend
        .list(StorePrefix::Roots, &mut |entry| {
            if let ListEntry::File { key, meta } = entry {
                assert_eq!(meta.len(), 1, "list reports sizes");
                roots.push(key);
            }
            ControlFlow::Continue(())
        })
        .expect("lists");
    assert_eq!(roots, [first, second]);
    assert_eq!(backend.delete(&first), Ok(DeleteOutcome::Deleted));
    assert_eq!(backend.delete(&first), Ok(DeleteOutcome::NotFound));
    assert_eq!(backend.stat(&first), Ok(None));
    assert_eq!(backend.stat(&second), Ok(Some(ObjectMeta::new(1))));
}
