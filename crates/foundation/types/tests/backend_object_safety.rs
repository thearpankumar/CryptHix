//! `Backend` is usable as a trait object, and its outcomes describe compare-and-swap.

use std::ops::ControlFlow;

use crypthix_testkit::MemoryBackend;
use crypthix_types::backend::{Backend, ByteRange, Capabilities, DeleteOutcome};
use crypthix_types::backend::{ListEntry, ObjectMeta, PutMode, PutOutcome, ReadMode};
use crypthix_types::id::{ConfigSeq, RootSeq};
use crypthix_types::store_key::{StoreKey, StorePrefix};

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
