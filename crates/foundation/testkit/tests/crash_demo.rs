//! The shape of a commit crash test (M-44, TV-20): a toy commit crashed at every step.
//!
//! The toy commit follows the order of format spec FS-87: write the shards, read them back
//! uncached and compare (FS-88), then create the next root without replacing. Whatever the
//! crash point, a restart must find the previous root intact, and a new root only if every
//! shard it names is complete.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crypthix_testkit::{CrashFailure, Fault, FaultBackend, MemoryBackend, for_each_crash_point};
use crypthix_types::backend::{Backend, BackendError, ByteRange, PutMode, PutOutcome, ReadMode};
use crypthix_types::id::{RootSeq, ShardId};
use crypthix_types::store_key::StoreKey;

const OLD_ROOT: &[u8] = b"root 1";
const NEW_ROOT: &[u8] = b"root 2: shards 1, 2, 3";

fn shard(n: u8) -> StoreKey {
    StoreKey::Shard(ShardId::try_from_bytes([n; 32]).expect("non-zero"))
}

fn root(seq: u64) -> StoreKey {
    let mut root = RootSeq::FIRST;
    for _ in 1..seq {
        root = root.checked_next().expect("small");
    }
    StoreKey::Root(root)
}

fn shard_bytes(n: u8) -> Vec<u8> {
    vec![n; 64]
}

fn whole(key: &StoreKey) -> ByteRange {
    ByteRange::prefix(key.max_file_len())
}

fn setup() -> MemoryBackend {
    MemoryBackend::from_files(BTreeMap::from([(root(1), OLD_ROOT.to_vec())]))
}

/// Creates `key` with `bytes`; a name already taken must hold exactly our bytes.
fn create(backend: &dyn Backend, key: &StoreKey, bytes: &[u8]) -> Result<(), BackendError> {
    if backend.put(key, bytes, PutMode::IfAbsent)? == PutOutcome::Created {
        return Ok(());
    }
    let stored = backend.get(key, whole(key), ReadMode::Uncached)?;
    if stored == bytes {
        Ok(())
    } else {
        Err(BackendError::Conflict)
    }
}

fn commit(backend: &dyn Backend) -> Result<(), BackendError> {
    for n in 1..=3 {
        create(backend, &shard(n), &shard_bytes(n))?;
    }
    for n in 1..=3 {
        let read = backend.get(&shard(n), whole(&shard(n)), ReadMode::Uncached)?;
        if read != shard_bytes(n) {
            return Err(BackendError::InvalidResponse);
        }
    }
    create(backend, &root(2), NEW_ROOT)
}

/// The bug FS-87 forbids: the root is linked before its shards are written.
fn root_first_commit(backend: &dyn Backend) -> Result<(), BackendError> {
    create(backend, &root(2), NEW_ROOT)?;
    for n in 1..=3 {
        create(backend, &shard(n), &shard_bytes(n))?;
    }
    Ok(())
}

fn invariants(store: &MemoryBackend) -> Result<(), String> {
    if store.file(&root(1)).as_deref() != Some(OLD_ROOT) {
        return Err("the previous root is gone or changed".to_owned());
    }
    match store.file(&root(2)) {
        None => Ok(()),
        Some(new) if new != NEW_ROOT => Err("the new root is torn".to_owned()),
        Some(_) => {
            for n in 1..=3 {
                if store.file(&shard(n)) != Some(shard_bytes(n)) {
                    return Err(format!("the new root names shard {n}, which is missing"));
                }
            }
            Ok(())
        }
    }
}

#[test]
fn every_crash_point_leaves_a_valid_root() {
    let mut points = Vec::new();
    let total = for_each_crash_point(setup, commit, |point, store| {
        points.push(point.after);
        if point.after == point.total && store.file(&root(2)).is_none() {
            return Err("a commit that ran to the end left no new root".to_owned());
        }
        invariants(store)
    })
    .expect("the commit order is crash safe");
    // Three shard writes, three read-backs and the root.
    assert_eq!(total, 7);
    assert_eq!(points, (0..=7).collect::<Vec<_>>(), "k = 0 through N");
}

#[test]
fn a_wrong_commit_order_is_caught_at_its_crash_point() {
    let failure = for_each_crash_point(setup, root_first_commit, |_, store| invariants(store))
        .expect_err("linking the root first is not crash safe");
    let CrashFailure::Invariant { point, message } = failure else {
        panic!("the dry run succeeds");
    };
    assert_eq!(point.after, 1, "a crash right after the root link");
    assert!(message.contains("shard 1"), "{message}");
}

#[test]
fn a_lost_reply_on_the_root_is_resolved_by_reading_back() {
    // Op 6 is the root create: it lands, but the caller sees a timeout and retries.
    let backend = FaultBackend::new(setup(), Fault::LostReplyAt(6));
    assert_eq!(commit(&backend), Err(BackendError::Unavailable));
    assert!(backend.applied(), "op 6 is the root create");
    assert_eq!(commit(&backend), Ok(()), "the retry finds its own root");
    invariants(&backend.into_inner()).expect("valid");
}

#[test]
fn corruption_on_the_way_to_disk_aborts_before_the_root() {
    // Op 3 is the read-back of shard 1.
    let backend = FaultBackend::new(setup(), Fault::CorruptUncachedReadAt(3));
    assert_eq!(commit(&backend), Err(BackendError::InvalidResponse));
    assert!(backend.applied(), "op 3 is an uncached read-back");
    assert_eq!(
        backend.into_inner().file(&root(2)),
        None,
        "no root links bad data"
    );
}

#[test]
fn a_dry_run_failure_is_reported() {
    let failure = for_each_crash_point(
        MemoryBackend::new,
        |_| Err::<(), _>(BackendError::QuotaExceeded),
        |_, _| Ok(()),
    );
    assert_eq!(
        failure,
        Err(CrashFailure::DryRun(BackendError::QuotaExceeded))
    );
}

#[test]
fn a_nondeterministic_workload_is_reported() {
    let runs = AtomicU64::new(0);
    // Each run writes a different shard first, so crash points do not line up with the dry run.
    let workload = |backend: &dyn Backend| {
        let run = runs.fetch_add(1, Ordering::Relaxed);
        let n = u8::try_from(run % 2 + 1).expect("small");
        create(backend, &shard(n), &shard_bytes(n))?;
        create(backend, &root(2), NEW_ROOT)
    };
    let failure = for_each_crash_point(setup, workload, |_, _| Ok(()));
    assert!(
        matches!(failure, Err(CrashFailure::Nondeterministic { .. })),
        "a workload that changes between runs is flagged: {failure:?}"
    );
}
