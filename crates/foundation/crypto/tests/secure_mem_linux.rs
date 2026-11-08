//! Protected key memory on a real Linux kernel (O1, T-31).
//!
//! Set `CRYPTHIX_REQUIRE_SECRETMEM=1` where `memfd_secret` is known to work, to fail instead of
//! skip when it does not.
#![cfg(all(target_os = "linux", not(miri)))]

mod secure_mem_accounting;

use std::io::{Read, Seek, SeekFrom};
use std::process::Command;

use crypthix_crypto::aad::Aad;
use crypthix_crypto::argon2id::{self, DeriveError, KdfParams};
use crypthix_crypto::cx_aead::{self, NonceKind, OpenError};
use crypthix_crypto::kdf::{self, KdfContext};
use crypthix_crypto::key::{KdfKey, KeyError, Passphrase, SealKey};
use crypthix_crypto::label::{AadLabel, SealKeyLabel, SigLabel};
use crypthix_crypto::secure_mem::{self, Config, Fallback, Level, MemError, SecretBuf};
use crypthix_crypto::sign::{SigningKey, VerifyError};
use crypthix_types::format_error::FormatError;
use rustix::process::{Pid, WaitOptions, WaitStatus};

use crate::secure_mem_accounting::{Accounting, HELD_PAGES, Holder};

/// Set, to the name of its test, in each child process [`in_child`] starts.
const CHILD: &str = "CRYPTHIX_TEST_CHILD";

/// Set by [`in_child_knowing_accounting`], in the child it starts, to the [`Accounting`] name
/// the probe found before the child lowered any limit.
const ACCOUNTING: &str = "CRYPTHIX_TEST_SECRETMEM_ACCOUNTING";

/// Set by `cargo xtask kernel-test --expect` to the [`Accounting`] name the booted kernel must
/// show, so a kernel picked for the wrong side of the CVE-2026-93243 fix fails the run.
const EXPECTED_ACCOUNTING: &str = "CRYPTHIX_EXPECT_SECRETMEM_ACCOUNTING";

/// Printed, with the [`Accounting`] name, by [`secret_memory_accounting_model`].
const ACCOUNTING_LINE: &str = "secret memory accounting: ";

/// Printed with the test's name by such a child when every check passed, so the test cannot pass
/// by running nothing or another test.
const CHILD_DONE: &str = "child checks passed:";

fn secretmem_required() -> bool {
    std::env::var_os("CRYPTHIX_REQUIRE_SECRETMEM").is_some_and(|value| value == "1")
}

/// The start addresses of this process's readable `memfd_secret` mappings, from
/// `/proc/self/maps`. The guard pages around each are separate, inaccessible mappings.
fn readable_secretmem_starts() -> Vec<u64> {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("procfs is mounted");
    maps.lines()
        .filter(|line| line.contains("secretmem"))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (start, _) = fields.next()?.split_once('-')?;
            fields
                .next()?
                .starts_with('r')
                .then(|| u64::from_str_radix(start, 16).ok())?
        })
        .collect()
}

#[test]
#[expect(clippy::print_stderr, reason = "a skipped check says so")]
fn keys_get_secret_memory_where_the_kernel_has_it() {
    let key = SealKey::random().expect("a key");
    let status = secure_mem::status();
    eprintln!("key level: {}, reason: {:?}", key.level(), status.reason);
    assert!(key.level() >= Level::DumpExcluded);
    assert_eq!(status.key_level, Some(key.level()));
    if secretmem_required() {
        assert_eq!(key.level(), Level::Secret, "{:?}", status.reason);
    }
    if key.level() != Level::Secret {
        eprintln!("memfd_secret is not available here; the secret checks are skipped");
        return;
    }
    let starts = readable_secretmem_starts();
    assert!(
        !starts.is_empty(),
        "no secretmem mapping in /proc/self/maps"
    );
    let mut mem = std::fs::File::open("/proc/self/mem").expect("procfs is mounted");
    for start in starts {
        mem.seek(SeekFrom::Start(start)).expect("seek");
        let mut byte = [0u8; 1];
        assert!(
            mem.read_exact(&mut byte).is_err(),
            "secret memory was readable through /proc/self/mem"
        );
    }
}

/// Probes how the kernel accounts secret memory ([`secure_mem_accounting`]) and prints it as
/// `secret memory accounting: <model>`. Where [`EXPECTED_ACCOUNTING`] names a model it must be
/// that one, and where `CRYPTHIX_REQUIRE_SECRETMEM=1` the kernel must have secret memory.
///
/// Ignored, because the probe holds secret pages of this user for a moment, which on a per-user
/// kernel could refuse a test running beside it. `cargo xtask kernel-test` runs it alone in
/// each kernel it boots; the tests that need the model run the probe themselves
/// ([`in_child_knowing_accounting`]).
#[test]
#[ignore = "probe: holds secret memory; `cargo xtask kernel-test` runs it alone"]
#[expect(clippy::print_stdout, reason = "the model is what this probe reports")]
fn secret_memory_accounting_model() {
    if std::env::var_os(CHILD).is_some() {
        child_stdout(PROBE, print_accounting, None);
        return;
    }
    let model = probed_accounting();
    println!("{ACCOUNTING_LINE}{}", model.name());
    if let Some(expected) = std::env::var_os(EXPECTED_ACCOUNTING) {
        let expected = expected
            .to_str()
            .and_then(Accounting::from_name)
            .unwrap_or_else(|| panic!("{EXPECTED_ACCOUNTING}={expected:?} names no model"));
        assert_eq!(
            model, expected,
            "this kernel accounts secret memory otherwise"
        );
    }
    if secretmem_required() {
        assert_ne!(
            model,
            Accounting::Unavailable,
            "CRYPTHIX_REQUIRE_SECRETMEM=1, but the kernel gives no secret memory"
        );
    }
}

#[test]
fn plaintext_is_locked_or_dump_excluded_never_secret() {
    let key = SealKey::random().expect("a key");
    let aad = Aad::new(AadLabel::BlobData).field(&[1; 16]);
    let sealed = cx_aead::seal(&key, &aad, b"plaintext", NonceKind::Hedged).expect("seals");
    let opened = cx_aead::open(&key, &aad, &sealed).expect("opens");
    let level = opened.level().expect("a non-empty buffer maps memory");
    assert!(
        (Level::DumpExcluded..=Level::Locked).contains(&level),
        "{level}"
    );
    assert_eq!(opened.as_slice(), b"plaintext");
}

/// Runs itself again with `RLIMIT_MEMLOCK` at zero: `init` with a minimum of `Locked` fails,
/// yet its pool stays, so every later key fails the same way instead of quietly getting the
/// default minimum, and `status` says why. Buffers fall back to `DumpExcluded`, and no page is
/// touched past the limit (on newer kernels that would be a `SIGBUS`, failing the child).
#[test]
fn a_failed_init_still_enforces_its_minimum() {
    in_child(
        "a_failed_init_still_enforces_its_minimum",
        child_with_no_memlock,
    );
}

fn child_with_no_memlock() {
    set_memlock_limit(0);
    let below = MemError::BelowMinimum {
        got: Level::DumpExcluded,
        want: Level::Locked,
    };
    assert_eq!(
        secure_mem::init(Config::default().with_minimum(Level::Locked)).err(),
        Some(below)
    );
    assert_eq!(
        SealKey::random().err(),
        Some(KeyError::Memory(below)),
        "a key after the failed init must still meet its minimum"
    );
    assert_eq!(
        secure_mem::init(Config::default()).err(),
        Some(MemError::AlreadyInitialised),
        "a second init cannot lower the minimum"
    );
    let status = secure_mem::status();
    assert_eq!(status.minimum, Level::Locked);
    assert_eq!(status.key_level, None, "no arena was kept");
    assert_eq!(status.key_slots_total, 0);
    assert_eq!(status.reason, Some(Fallback::LockLimit));
    assert_eq!(status.last_failure, Some(below));
    let buf = SecretBuf::try_copy_from(b"x").expect("memory for a buffer");
    assert_eq!(buf.level(), Some(Level::DumpExcluded));
}

/// Runs itself again with `RLIMIT_MEMLOCK` at one page and a pool of one-page arenas that must
/// be locked: the first arena locks, every key in it works, and the key past it fails with
/// `BelowMinimum` while `status` still reports the existing keys as locked, with the lock limit
/// as the reason and the failure beside it.
#[test]
fn a_later_arena_below_the_minimum_fails_only_its_own_keys() {
    in_child(
        "a_later_arena_below_the_minimum_fails_only_its_own_keys",
        child_with_one_lockable_page,
    );
}

fn child_with_one_lockable_page() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(page).expect("a page size fits in u64"));
    let config = Config::default()
        .with_strongest(Level::Locked)
        .with_minimum(Level::Locked)
        .with_pages_per_arena(1)
        .with_max_pages(64);
    let status = secure_mem::init(config).expect("one page can be locked");
    assert_eq!(status.key_level, Some(Level::Locked));
    assert_eq!(status.reason, None, "the strongest level was reached");
    assert_eq!(status.last_failure, None);
    let mut keys: Vec<SealKey> = (0..status.key_slots_total)
        .map(|_| SealKey::random().expect("a free slot in the locked arena"))
        .collect();
    assert!(keys.iter().all(|key| key.level() == Level::Locked));
    let below = MemError::BelowMinimum {
        got: Level::DumpExcluded,
        want: Level::Locked,
    };
    assert_eq!(SealKey::random().err(), Some(KeyError::Memory(below)));
    let status = secure_mem::status();
    assert_eq!(
        status.key_level,
        Some(Level::Locked),
        "every key that exists is locked"
    );
    assert_eq!(status.reason, Some(Fallback::LockLimit));
    assert_eq!(status.last_failure, Some(below));
    assert_eq!(status.key_slots_used, keys.len());
    keys.pop();
    let reused = SealKey::random().expect("a freed slot is reused");
    assert_eq!(reused.level(), Level::Locked);
}

/// Runs itself again with `RLIMIT_MEMLOCK` at 16 pages and a pool of up to four one-page
/// arenas that must be locked, which keeps 12 pages (4 data, 8 guard) for keys: a buffer may
/// lock the other 4 pages but no more, and with them held every arena the pool can add still
/// locks.
#[test]
fn locked_buffers_cannot_starve_the_key_arenas() {
    in_child(
        "locked_buffers_cannot_starve_the_key_arenas",
        child_with_buffers_holding_their_share,
    );
}

fn child_with_buffers_holding_their_share() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(16 * page).expect("16 pages fit in u64"));
    let config = Config::default()
        .with_strongest(Level::Locked)
        .with_minimum(Level::Locked)
        .with_pages_per_arena(1)
        .with_max_pages(4);
    let status = secure_mem::init(config).expect("one page can be locked");
    let per_arena = status.key_slots_total;
    let held = SecretBuf::try_zeroed(4 * page).expect("memory for a buffer");
    assert_eq!(
        held.level(),
        Some(Level::Locked),
        "buffers lock what the keys leave"
    );
    let over = SecretBuf::try_zeroed(1).expect("memory for a buffer");
    assert_eq!(
        over.level(),
        Some(Level::DumpExcluded),
        "buffers lock nothing of the key reserve, though the limit has room"
    );
    let keys: Vec<SealKey> = (0..4 * per_arena)
        .map(|_| SealKey::random().expect("every arena the pool may add locks"))
        .collect();
    assert!(keys.iter().all(|key| key.level() == Level::Locked));
    let status = secure_mem::status();
    assert_eq!(status.key_slots_total, 4 * per_arena, "all four arenas");
    assert_eq!(status.key_level, Some(Level::Locked));
    assert_eq!(status.last_failure, None);
    assert_eq!(
        SealKey::random().err(),
        Some(KeyError::Memory(MemError::PoolExhausted)),
        "the pool's own cap, not the lock limit, ends it"
    );
    drop(held);
    assert_eq!(
        SecretBuf::try_zeroed(4 * page)
            .expect("memory for a buffer")
            .level(),
        Some(Level::Locked),
        "a freed buffer returns its share"
    );
}

/// Runs itself again, so no buffer exists yet: a seal opened with the wrong key fails at the
/// commitment without making a plaintext buffer, so `status` still reports none; a good one
/// makes one.
#[test]
fn a_failed_commitment_makes_no_plaintext_buffer() {
    in_child(
        "a_failed_commitment_makes_no_plaintext_buffer",
        child_opening_a_forgery,
    );
}

fn child_opening_a_forgery() {
    let key = SealKey::random().expect("a key");
    let other = SealKey::random().expect("a key");
    let aad = Aad::new(AadLabel::BlobData).field(&[4; 16]);
    let sealed = cx_aead::seal(&key, &aad, &[7; 10_000], NonceKind::Hedged).expect("seals");
    assert_eq!(secure_mem::status().buffer_level, None, "no buffer yet");
    assert_eq!(
        cx_aead::open(&other, &aad, &sealed).err(),
        Some(OpenError::Format(FormatError::Decrypt))
    );
    assert_eq!(
        secure_mem::status().buffer_level,
        None,
        "a failed commitment made a plaintext buffer"
    );
    let opened = cx_aead::open(&key, &aad, &sealed).expect("opens");
    assert_eq!(secure_mem::status().buffer_level, opened.level());
}

/// Runs itself again with the address space capped two pages above what it already uses, so
/// the kernel can map no buffer (each is at least three pages: a guard on each side of the data)
/// while the heap still has room. The buffer is refused rather than put on the heap, `status`
/// keeps reporting the level of the buffers that exist and says the kernel refused the latest.
/// Opening a genuine seal, signing, verifying and taking a passphrase each return that memory
/// error instead of aborting, and a forged seal is still the opaque `Decrypt`: its commitment
/// fails before any buffer is asked for. This is how a process that has used up
/// `vm.max_map_count` sees it too.
#[test]
fn a_buffer_the_kernel_will_not_map_is_refused_not_put_on_the_heap() {
    in_child(
        "a_buffer_the_kernel_will_not_map_is_refused_not_put_on_the_heap",
        child_with_no_address_space_left,
    );
}

fn child_with_no_address_space_left() {
    let first = SecretBuf::try_copy_from(b"x").expect("memory for a buffer");
    let level = first.level();
    assert!(level >= Some(Level::DumpExcluded), "{level:?}");
    let status = secure_mem::status();
    assert_eq!(status.buffer_level, level);
    let reason = status.buffer_reason;
    let key = SealKey::random().expect("a key");
    let other = SealKey::random().expect("a key");
    let aad = Aad::new(AadLabel::BlobData).field(&[5; 16]);
    let sealed = cx_aead::seal(&key, &aad, b"plaintext", NonceKind::Hedged).expect("seals");
    let signer = SigningKey::random().expect("a key");
    let verifier = signer.verifying_key();
    let signature = signer
        .sign(SigLabel::Root, &[1; 16], b"body")
        .expect("signs");
    let text = String::from("correct horse battery staple");
    let unlimited = cap_address_space();
    let too_large = SecretBuf::try_zeroed(usize::MAX).map(|buf| buf.level());
    let after_too_large = secure_mem::status().buffer_reason;
    let refused = SecretBuf::try_zeroed(1).map(|buf| buf.level());
    let after = secure_mem::status();
    let forged = cx_aead::open(&other, &aad, &sealed).map(|buf| buf.level());
    let opened = cx_aead::open(&key, &aad, &sealed).map(|buf| buf.level());
    let sign_result = signer.sign(SigLabel::Root, &[1; 16], b"body");
    let verify_result = verifier.verify(SigLabel::Root, &[1; 16], b"body", &signature);
    let passphrase = Passphrase::new(text).map(|_| ());
    restore_address_space(unlimited);
    assert_eq!(too_large, Err(MemError::TooLarge), "no mapping was tried");
    assert_eq!(after_too_large, reason, "a size refusal records no reason");
    assert_eq!(
        refused,
        Err(MemError::MapFailed),
        "a buffer outside a mapping"
    );
    assert_eq!(
        after.buffer_level, level,
        "status changed though no buffer was made"
    );
    assert_eq!(after.buffer_reason, Some(Fallback::KernelRefused));
    assert_eq!(
        forged,
        Err(OpenError::Format(FormatError::Decrypt)),
        "the commitment fails before a buffer is asked for"
    );
    assert_eq!(
        opened,
        Err(OpenError::Memory(MemError::MapFailed)),
        "memory, never Decrypt"
    );
    assert_eq!(sign_result, Err(MemError::MapFailed));
    assert_eq!(
        verify_result,
        Err(VerifyError::Memory(MemError::MapFailed)),
        "memory, never Signature"
    );
    assert_eq!(passphrase, Err(MemError::MapFailed));
    assert_eq!(
        cx_aead::open(&key, &aad, &sealed)
            .expect("opens with room again")
            .as_slice(),
        b"plaintext"
    );
}

/// Caps this process's address space two pages above what it already uses, so the kernel maps
/// nothing more (a mapping of protected memory is at least three pages), after freeing some heap
/// memory so a small heap allocation still needs no new mapping. Returns the limit to restore.
fn cap_address_space() -> rustix::process::Rlimit {
    use rustix::process::{self, Resource};

    drop(std::hint::black_box(Vec::<u8>::with_capacity(64 * 1024)));
    let page = rustix::param::page_size();
    let used = address_space_in_use();
    let unlimited = process::getrlimit(Resource::As);
    let mut capped = unlimited;
    capped.current = Some(used + 2 * u64::try_from(page).expect("a page size fits in u64"));
    process::setrlimit(Resource::As, capped).expect("lowering a soft limit is always allowed");
    unlimited
}

/// Undoes [`cap_address_space`].
fn restore_address_space(unlimited: rustix::process::Rlimit) {
    use rustix::process::{self, Resource};

    process::setrlimit(Resource::As, unlimited).expect("the hard limit was not lowered");
}

/// The bytes of address space this process has mapped (`VmSize` in `/proc/self/status`).
fn address_space_in_use() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("procfs is mounted");
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmSize:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .expect("a VmSize line in kB");
    kib * 1024
}

/// Runs itself again, so the pool is its own: a successful `init` reports the one arena it
/// mapped, a second `init` is refused without changing it, and the pool's cap of one page ends
/// key making with `PoolExhausted` through the public key API until a key is dropped, whose
/// slot the next key takes.
#[test]
fn init_once_then_the_pool_cap_through_the_key_api() {
    in_child(
        "init_once_then_the_pool_cap_through_the_key_api",
        child_with_a_one_page_pool,
    );
}

fn child_with_a_one_page_pool() {
    let per_page = rustix::param::page_size() / 32;
    let status = secure_mem::init(Config::default().with_pages_per_arena(1).with_max_pages(1))
        .expect("a one-page pool");
    assert_eq!(
        status.key_slots_total, per_page,
        "one page of 32-byte slots"
    );
    assert_eq!(status.key_slots_used, 0);
    assert_eq!(status.last_failure, None);
    assert_eq!(
        secure_mem::init(Config::default().with_pages_per_arena(4).with_max_pages(64)).err(),
        Some(MemError::AlreadyInitialised)
    );
    assert_eq!(
        secure_mem::status(),
        status,
        "the refused init changed nothing"
    );
    let mut keys: Vec<SealKey> = (0..per_page)
        .map(|_| SealKey::random().expect("a free slot"))
        .collect();
    assert_eq!(
        SealKey::random().err(),
        Some(KeyError::Memory(MemError::PoolExhausted))
    );
    assert_eq!(
        SigningKey::random().err(),
        Some(KeyError::Memory(MemError::PoolExhausted)),
        "every key type shares the pool"
    );
    let full = secure_mem::status();
    assert_eq!(
        (full.key_slots_used, full.key_slots_total),
        (per_page, per_page)
    );
    assert_eq!(full.last_failure, Some(MemError::PoolExhausted));
    keys.swap_remove(per_page / 2);
    let reused = SealKey::random().expect("the freed slot is taken again");
    assert_eq!(reused.level(), keys[0].level(), "in the same arena");
    assert_eq!(secure_mem::status().key_slots_used, per_page);
}

/// Runs itself again, so the slot count is this test's alone: keys and buffers made on one
/// thread are used and dropped on others, while those threads make keys of their own that the
/// first thread drops, over many rounds. Every seal opens and every signature verifies, and
/// every slot comes back.
#[test]
fn keys_cross_threads_and_every_slot_comes_back() {
    in_child(
        "keys_cross_threads_and_every_slot_comes_back",
        child_with_keys_on_many_threads,
    );
}

fn child_with_keys_on_many_threads() {
    const THREADS: u8 = 8;
    const ROUNDS: usize = 50;
    let start = secure_mem::status().key_slots_used;
    let shared = SealKey::random().expect("a key");
    let aad = Aad::new(AadLabel::BlobData).field(&[5; 16]);
    let shared_seal = cx_aead::seal(
        &shared,
        &aad,
        b"made on the first thread",
        NonceKind::Hedged,
    )
    .expect("seals");
    for round in 0..ROUNDS {
        let made: Vec<(SealKey, SigningKey, SecretBuf)> = (0..THREADS)
            .map(|thread| {
                (
                    SealKey::random().expect("a key"),
                    SigningKey::random().expect("a key"),
                    SecretBuf::try_copy_from(&[thread; 100]).expect("memory for a buffer"),
                )
            })
            .collect();
        let returned: Vec<SealKey> = std::thread::scope(|scope| {
            let handles: Vec<_> = made
                .into_iter()
                .enumerate()
                .map(|(index, (seal_key, signing_key, buf))| {
                    let (shared, aad, shared_seal) = (&shared, &aad, &shared_seal);
                    scope.spawn(move || {
                        let tag = u8::try_from(index).expect("few threads");
                        assert_eq!(buf.as_slice(), &[tag; 100]);
                        let sealed =
                            cx_aead::seal(&seal_key, aad, &buf, NonceKind::Hedged).expect("seals");
                        let opened = cx_aead::open(&seal_key, aad, &sealed).expect("opens");
                        assert_eq!(opened.as_slice(), buf.as_slice());
                        let opened = cx_aead::open(shared, aad, shared_seal).expect("opens");
                        assert_eq!(opened.as_slice(), b"made on the first thread");
                        let ctx = [tag; 16];
                        let signature =
                            signing_key.sign(SigLabel::Root, &ctx, &buf).expect("signs");
                        signing_key
                            .verifying_key()
                            .verify(SigLabel::Root, &ctx, &buf, &signature)
                            .expect("the signature verifies");
                        drop((seal_key, signing_key, buf));
                        SealKey::random().expect("a key made on this thread")
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("the thread's checks passed"))
                .collect()
        });
        assert_eq!(returned.len(), usize::from(THREADS), "round {round}");
        assert_eq!(
            secure_mem::status().key_slots_used,
            start + 1 + returned.len(),
            "round {round}: only the shared key and the returned ones are left"
        );
    }
    drop(shared);
    assert_eq!(
        secure_mem::status().key_slots_used,
        start,
        "every slot came back"
    );
}

/// Runs itself again with `RLIMIT_MEMLOCK` at 8 pages and a one-page pool, which keeps 3 of
/// them for keys: opened plaintext is locked, and `status` says so with no reason; with the
/// limit then at zero the next is only left out of core dumps, and `status` reports that weaker
/// level and the lock limit as its reason, which a later locked buffer does not clear.
#[test]
fn status_reports_the_weakest_plaintext_buffer() {
    in_child(
        "status_reports_the_weakest_plaintext_buffer",
        child_opening_under_two_limits,
    );
}

fn child_opening_under_two_limits() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(8 * page).expect("8 pages fit in u64"));
    secure_mem::init(Config::default().with_pages_per_arena(1).with_max_pages(1))
        .expect("one page for keys");
    let key = SealKey::random().expect("a key");
    let aad = Aad::new(AadLabel::BlobData).field(&[6; 16]);
    let sealed = cx_aead::seal(&key, &aad, b"plaintext", NonceKind::Hedged).expect("seals");
    let locked = cx_aead::open(&key, &aad, &sealed).expect("opens");
    assert_eq!(locked.level(), Some(Level::Locked));
    let status = secure_mem::status();
    assert_eq!(status.buffer_level, Some(Level::Locked));
    assert_eq!(status.buffer_reason, None, "every buffer so far is locked");
    let eight_pages = u64::try_from(8 * page).expect("8 pages fit in u64");
    set_soft_memlock_limit(0, eight_pages);
    let excluded = cx_aead::open(&key, &aad, &sealed).expect("opens");
    assert_eq!(excluded.level(), Some(Level::DumpExcluded));
    assert_eq!(excluded.as_slice(), b"plaintext");
    let status = secure_mem::status();
    assert_eq!(status.buffer_level, Some(Level::DumpExcluded));
    assert_eq!(status.buffer_reason, Some(Fallback::LockLimit));
    drop(excluded);
    assert_eq!(
        secure_mem::status().buffer_level,
        Some(Level::DumpExcluded),
        "the weakest so far, even once that buffer is gone"
    );
    assert_eq!(locked.as_slice(), b"plaintext");
    drop(locked);
    set_soft_memlock_limit(eight_pages, eight_pages);
    let relocked = SecretBuf::try_zeroed(1).expect("memory for a buffer");
    assert_eq!(
        relocked.level(),
        Some(Level::Locked),
        "the share is free again"
    );
    assert_eq!(
        secure_mem::status().buffer_reason,
        Some(Fallback::LockLimit),
        "a later locked buffer leaves the reason"
    );
}

/// Runs itself again with `RLIMIT_MEMLOCK` at the usual 8 MiB (or below) and a one-page pool,
/// then derives a key with Argon2id at the FS-41 floor: the 256 MiB of blocks cannot be
/// locked, so they are left out of core dumps instead (the passphrase's small buffer, made
/// first, is locked, so the weaker level `status` reports is the blocks'), and the key is made
/// in its own memory as usual and works.
#[test]
#[ignore = "slow: Argon2id over 256 MiB (FS-41 floor); run with --ignored"]
fn argon2_blocks_past_the_lock_limit_are_dump_excluded() {
    in_child(
        "argon2_blocks_past_the_lock_limit_are_dump_excluded",
        child_deriving_at_the_floor,
    );
}

fn child_deriving_at_the_floor() {
    // The usual limit, or less where the hard limit is lower: the passphrase still locks.
    let current = rustix::process::getrlimit(rustix::process::Resource::Memlock).current;
    set_memlock_limit(current.map_or(8 << 20, |bytes| bytes.min(8 << 20)));
    secure_mem::init(Config::default().with_pages_per_arena(1).with_max_pages(1))
        .expect("one page for keys");
    let passphrase = Passphrase::new("correct horse battery staple".to_owned()).expect("a buffer");
    assert_eq!(secure_mem::status().buffer_level, Some(Level::Locked));
    let params =
        KdfParams::new(KdfParams::MIN_M_COST, KdfParams::MIN_T_COST, 1).expect("at the floor");
    let key = argon2id::derive(&passphrase, &[7; 32], &params).expect("derives");
    let status = secure_mem::status();
    assert_eq!(status.buffer_level, Some(Level::DumpExcluded));
    assert_eq!(status.key_level, Some(key.level()));
    assert!(key.level() >= Level::Locked, "{:?}", status.reason);
    let aad = Aad::new(AadLabel::BlobData).field(&[8; 16]);
    let sealed = cx_aead::seal(&key, &aad, b"after argon2", NonceKind::Hedged).expect("seals");
    let opened = cx_aead::open(&key, &aad, &sealed).expect("opens");
    assert_eq!(opened.as_slice(), b"after argon2");
}

/// Runs `checks` as the test `name` in a fresh process: this test binary again, with [`CHILD`]
/// set to `name`, running only that test (`--exact`, and `--include-ignored` so a slow test
/// runs in its child too) on one thread, so nothing else in it maps, locks or forks. Checks
/// that the child ran exactly one test, which passed and printed [`CHILD_DONE`] with `name`.
///
/// The child's standard error, where a skipped check says so, is passed on to this test's, so
/// the skip shows wherever the test's output does (see `.config/nextest.toml`).
fn in_child(name: &str, checks: fn()) {
    child_stdout(name, checks, None);
}

/// [`in_child`], for checks that depend on how the kernel accounts secret memory: the probe
/// runs first, in a fresh process with this test's limits, and the child gets its result in
/// [`ACCOUNTING`], which [`accounting`] reads.
fn in_child_knowing_accounting(name: &str, checks: fn()) {
    let model = std::env::var_os(CHILD).is_none().then(probed_accounting);
    child_stdout(name, checks, model);
}

/// What [`in_child`] does, passing `model` to the child if given; returns the child's standard
/// output, or nothing in the child itself.
#[expect(clippy::print_stdout, reason = "tells the parent test the checks ran")]
#[expect(
    clippy::print_stderr,
    reason = "passes on what the child said, such as a skip"
)]
fn child_stdout(name: &str, checks: fn(), model: Option<Accounting>) -> String {
    if let Some(child) = std::env::var_os(CHILD) {
        assert_eq!(child, name, "a child runs only the test it was started for");
        checks();
        println!("{CHILD_DONE} {name}");
        return String::new();
    }
    let mut command = Command::new(std::env::current_exe().expect("test binary"));
    command
        .args([
            name,
            "--exact",
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, name);
    if let Some(model) = model {
        command.env(ACCOUNTING, model.name());
    }
    let output = command.output().expect("the test binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success()
            && stdout.contains(&format!("{CHILD_DONE} {name}\n"))
            && stdout.contains("test result: ok. 1 passed;"),
        "child failed: {:?}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    stdout
}

/// The test that runs the probe; see [`secret_memory_accounting_model`].
const PROBE: &str = "secret_memory_accounting_model";

/// Probes the kernel's [`Accounting`] in a fresh process running [`PROBE`].
fn probed_accounting() -> Accounting {
    let stdout = child_stdout(PROBE, print_accounting, None);
    let name = stdout
        .lines()
        // The harness may have started the line with the test's name.
        .find_map(|line| line.split_once(ACCOUNTING_LINE).map(|(_, name)| name))
        .unwrap_or_else(|| panic!("the probe printed no model:\n{stdout}"));
    Accounting::from_name(name).unwrap_or_else(|| panic!("an unknown model: {name}"))
}

#[expect(clippy::print_stdout, reason = "the probe's result goes to its parent")]
fn print_accounting() {
    println!("{ACCOUNTING_LINE}{}", secure_mem_accounting::probe().name());
}

/// The kernel's [`Accounting`], as [`in_child_knowing_accounting`] passed it to this child.
fn accounting() -> Accounting {
    let name = std::env::var(ACCOUNTING).expect("started by in_child_knowing_accounting");
    Accounting::from_name(&name).unwrap_or_else(|| panic!("an unknown model: {name}"))
}

/// Lowers this process's `RLIMIT_MEMLOCK`, soft and hard, to `bytes`.
fn set_memlock_limit(bytes: u64) {
    use rustix::process::{self, Resource, Rlimit};

    process::setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(bytes),
            maximum: Some(bytes),
        },
    )
    .expect("lowering a limit is always allowed");
}

/// Sets this process's soft `RLIMIT_MEMLOCK` to `bytes`, keeping the hard limit at `maximum`, so
/// the soft limit can be raised again.
fn set_soft_memlock_limit(bytes: u64, maximum: u64) {
    use rustix::process::{self, Resource, Rlimit};

    process::setrlimit(
        Resource::Memlock,
        Rlimit {
            current: Some(bytes),
            maximum: Some(maximum),
        },
    )
    .expect("a soft limit up to the hard limit is always allowed");
}

/// Runs itself again as a process that runs only this test, so forking is safe, then forks:
/// the child drops the keys and buffers it inherited (which must not touch the unmapped or
/// reused addresses), makes a key in a fresh pool of its own, and a grandchild that uses an
/// inherited key must panic rather than read memory that is not its own.
#[test]
fn a_forked_child_leaves_inherited_keys_alone_and_makes_its_own() {
    in_child(
        "a_forked_child_leaves_inherited_keys_alone_and_makes_its_own",
        fork_and_check,
    );
}

fn fork_and_check() {
    let key = SealKey::random().expect("a key");
    let buf = SecretBuf::try_copy_from(b"parent plaintext").expect("memory for a buffer");
    let aad = Aad::new(AadLabel::BlobData).field(&[2; 16]);
    let sealed =
        cx_aead::seal(&key, &aad, b"sealed by the parent", NonceKind::Hedged).expect("seals");
    let parent_level = key.level();
    let Some(child) = fork() else {
        run_child(|| child_checks(key, buf, parent_level));
    };
    let status = wait(child);
    assert_eq!(
        status.exit_status(),
        Some(0),
        "the forked child failed: {status:?}"
    );
    let opened = cx_aead::open(&key, &aad, &sealed).expect("the parent's key still works");
    assert_eq!(opened.as_slice(), b"sealed by the parent");
    assert_eq!(buf.as_slice(), b"parent plaintext");
}

/// What the forked child checks; a failed check panics, which ends the child with 101.
fn child_checks(key: SealKey, buf: SecretBuf, parent_level: Level) {
    let fresh = SealKey::random().expect("the child gets a pool of its own");
    let status = secure_mem::status();
    assert_eq!(
        status.key_slots_used, 1,
        "the parent's slots are not in the child's pool"
    );
    assert_eq!(
        fresh.level(),
        parent_level,
        "the parent's lock budget does not count in the child"
    );
    let aad = Aad::new(AadLabel::BlobData).field(&[3; 16]);
    let sealed = cx_aead::seal(&fresh, &aad, b"child", NonceKind::Hedged).expect("seals");
    let Some(grandchild) = fork() else {
        run_child(|| {
            // Expected to panic before it returns, so there is no result to look at.
            drop(cx_aead::seal(&key, &aad, b"x", NonceKind::Hedged));
        });
    };
    let used = wait(grandchild);
    assert_eq!(
        used.exit_status(),
        Some(101),
        "using an inherited key: {used:?}"
    );
    // The new arena may sit where the parent's was; dropping must not wipe or unmap it.
    drop(key);
    drop(buf);
    let opened = cx_aead::open(&fresh, &aad, &sealed).expect("the child's key is intact");
    assert_eq!(opened.as_slice(), b"child");
    assert_eq!(secure_mem::status().key_slots_used, 1);
}

/// Runs itself again with `RLIMIT_MEMLOCK` at four pages and a pool of one one-page arena, which
/// keeps three pages (data and guards) for keys and leaves one for buffers. The parent makes a
/// key and fills the buffers' page, so a second buffer is only `DumpExcluded`; then it forks.
/// None of those mappings is in the child (`MADV_DONTFORK`, and `mlock` is not inherited), so
/// the child's own limit gives it what it gave the parent: its key arena at the parent's level,
/// a locked buffer, and a `status` that reports only its own buffers.
///
/// Kernels with the CVE-2026-93243 fix charge secret pages to the user, so the parent's and the
/// child's arenas (one faulted-in page each; guard pages are never touched) share the limit of
/// four pages with every other secret page of the same user. As with
/// [`a_secret_arena_fits_a_limit_of_its_data_and_guard_pages`], `.config/nextest.toml` runs it
/// alone, and a child refused for other secret memory of the user skips the level check, which
/// only a kernel the probe found to charge per user may do ([`secret_refused_per_user`]).
#[test]
fn a_forked_child_gets_the_levels_its_own_limit_allows() {
    in_child_knowing_accounting(
        "a_forked_child_gets_the_levels_its_own_limit_allows",
        fork_with_the_lock_limit_used_up,
    );
}

fn fork_with_the_lock_limit_used_up() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(4 * page).expect("four pages fit in u64"));
    let config = Config::default().with_pages_per_arena(1).with_max_pages(1);
    secure_mem::init(config).expect("one arena fits the limit");
    let key = SealKey::random().expect("a slot in the arena");
    let key_level = key.level();
    if secretmem_required() {
        assert_eq!(
            key_level,
            Level::Secret,
            "the arena's three pages fit the limit"
        );
    }
    assert!(key_level >= Level::Locked, "{key_level}");
    let locked = SecretBuf::try_zeroed(page).expect("memory for a buffer");
    assert_eq!(locked.level(), Some(Level::Locked), "the buffers' page");
    let over = SecretBuf::try_zeroed(1).expect("memory for a buffer");
    assert_eq!(
        over.level(),
        Some(Level::DumpExcluded),
        "the buffers' page is used"
    );
    let status = secure_mem::status();
    assert_eq!(status.buffer_level, Some(Level::DumpExcluded));
    assert_eq!(status.buffer_reason, Some(Fallback::LockLimit));
    let Some(child) = fork() else {
        run_child(|| {
            let status = secure_mem::init(config.with_minimum(Level::Locked))
                .expect("the child's own limit has room for its arena");
            let child_level = if status.key_level == Some(key_level) {
                key_level
            } else {
                assert_eq!(key_level, Level::Secret, "{status:?}");
                assert!(secret_refused_per_user(&status), "{status:?}");
                Level::Locked
            };
            assert_eq!(
                (status.buffer_level, status.buffer_reason),
                (None, None),
                "the parent's buffers are not the child's"
            );
            let own = SealKey::random().expect("a slot in the child's arena");
            assert_eq!(own.level(), child_level);
            let buf = SecretBuf::try_zeroed(1).expect("memory for a buffer");
            assert_eq!(
                buf.level(),
                Some(Level::Locked),
                "the child's page for buffers is free"
            );
            let status = secure_mem::status();
            assert_eq!(status.buffer_level, Some(Level::Locked));
            assert_eq!(status.buffer_reason, None, "the child's buffer is locked");
        });
    };
    let status = wait(child);
    assert_eq!(
        status.exit_status(),
        Some(0),
        "the forked child failed: {status:?}"
    );
    drop((key, locked, over));
}

/// Forks: the child's pid in the parent, `None` in the child.
#[expect(unsafe_code, reason = "fork has no safe interface")]
fn fork() -> Option<Pid> {
    // SAFETY: the process runs only this test on one thread (`--exact`, `--test-threads=1`),
    // so no other thread holds a lock the child needs; the child ends in `run_child`.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    Pid::from_raw(pid)
}

/// Runs `body` as the whole of a forked child: exit status 0 if it returns, 101 if it panics.
#[expect(unsafe_code, reason = "_exit has no safe interface")]
#[expect(clippy::print_stderr, reason = "a failed check says why")]
fn run_child(body: impl FnOnce()) -> ! {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("forked child: {info}");
        // SAFETY: `_exit` ends the process at once, without unwinding into the test harness
        // the child copied from its parent.
        unsafe { libc::_exit(101) }
    }));
    body();
    // SAFETY: as above.
    unsafe { libc::_exit(0) }
}

fn wait(child: Pid) -> WaitStatus {
    let (_, status) = rustix::process::waitpid(Some(child), WaitOptions::empty())
        .expect("waitpid")
        .expect("the child was waited for");
    status
}

/// Runs itself again, so forking is safe, and reads single bytes of a one-page buffer from
/// forked children of its own: the last data byte reads back, while the byte before the data
/// and the byte after it, in the guard pages, kill the reader with `SIGSEGV`.
#[test]
fn reading_past_either_end_of_a_buffer_faults() {
    in_child(
        "reading_past_either_end_of_a_buffer_faults",
        read_around_a_buffer,
    );
}

fn read_around_a_buffer() {
    let page = isize::try_from(rustix::param::page_size()).expect("a page size fits in isize");
    assert_eq!(read_in_a_child(page - 1), None, "the probe itself works");
    assert_eq!(read_in_a_child(-1), Some(libc::SIGSEGV), "the guard below");
    assert_eq!(
        read_in_a_child(page),
        Some(libc::SIGSEGV),
        "the guard above"
    );
}

/// The signal that killed a forked child which made a one-page buffer of `0x5a` bytes and read
/// the byte `offset` bytes from its start; `None` if it read `0x5a` and exited.
fn read_in_a_child(offset: isize) -> Option<i32> {
    let Some(child) = fork() else {
        run_child(|| {
            no_core_dump();
            let buf = SecretBuf::try_copy_from(&vec![0x5a; rustix::param::page_size()])
                .expect("memory for a buffer");
            let address = buf.as_ptr().wrapping_offset(offset);
            #[expect(
                unsafe_code,
                reason = "reads at a guard page on purpose, to show it faults"
            )]
            // SAFETY: inside the buffer this reads an initialised byte of memory the child
            // has. Outside it, at a guard page, the read is a deliberate fault: the guard has no
            // access, so the CPU traps before any byte is read and the kernel ends this forked
            // child with `SIGSEGV`, which the parent checks. The child runs nothing else and
            // writes no core dump, so that signal is the fault's only effect.
            let byte = unsafe { address.read_volatile() };
            assert_eq!(byte, 0x5a);
        });
    };
    let status = wait(child);
    let signal = status.terminating_signal();
    if signal.is_none() {
        assert_eq!(status.exit_status(), Some(0), "{status:?}");
    }
    signal
}

/// Runs itself again, so forking is safe: a buffer's bytes stay with the process that made it.
/// A forked child that reads them through the buffer panics before touching them, and one that
/// reads their address directly faults, since the pages are not mapped in it
/// (`MADV_DONTFORK`). The parent's copy is intact afterwards.
#[test]
fn a_forked_child_cannot_read_an_inherited_buffer() {
    in_child(
        "a_forked_child_cannot_read_an_inherited_buffer",
        read_an_inherited_buffer,
    );
}

fn read_an_inherited_buffer() {
    let buf = SecretBuf::try_copy_from(b"parent plaintext").expect("memory for a buffer");
    let address = buf.as_ptr();
    let Some(child) = fork() else {
        run_child(|| {
            // Expected to panic before it reads; `black_box` keeps the read from being
            // optimised away.
            std::hint::black_box(buf.as_slice()[0]);
        });
    };
    let through_the_buffer = wait(child);
    assert_eq!(
        through_the_buffer.exit_status(),
        Some(101),
        "{through_the_buffer:?}"
    );
    let Some(child) = fork() else {
        run_child(|| {
            no_core_dump();
            #[expect(
                unsafe_code,
                reason = "reads an address not mapped in the child on purpose, to show it faults"
            )]
            // SAFETY: a deliberate fault. The pages are not mapped in this forked child
            // (`MADV_DONTFORK`), so the CPU traps before any byte is read and the kernel ends
            // the child with `SIGSEGV`, which the parent checks. The child runs nothing else and
            // writes no core dump, so that signal is the fault's only effect.
            std::hint::black_box(unsafe { address.read_volatile() });
        });
    };
    let direct = wait(child);
    assert_eq!(
        direct.terminating_signal(),
        Some(libc::SIGSEGV),
        "{direct:?}"
    );
    assert_eq!(buf.as_slice(), b"parent plaintext");
}

/// Keeps an expected crash of this forked child from writing a core dump.
fn no_core_dump() {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .expect("a process may always make itself not dumpable");
}

/// Runs itself again with `RLIMIT_MEMLOCK` at one page, the data of one one-page arena but not
/// its guard pages, which the lock budget charges a `memfd_secret` mapping for too: the key
/// arena falls back to `Locked` because the budget refuses the secret mapping (`LockLimit`).
/// Kernels that check the whole mapping when it is mapped would refuse it too (`EAGAIN` from
/// `mmap`); kernels that charge pages as they are faulted in would have allowed it.
#[test]
fn a_secret_arena_needs_room_for_its_guard_pages() {
    in_child(
        "a_secret_arena_needs_room_for_its_guard_pages",
        child_with_room_for_the_data_only,
    );
}

fn child_with_room_for_the_data_only() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(page).expect("a page size fits in u64"));
    let status = secure_mem::init(Config::default().with_pages_per_arena(1).with_max_pages(1))
        .expect("a locked arena");
    assert_eq!(status.key_level, Some(Level::Locked));
    assert_eq!(status.reason, Some(Fallback::LockLimit));
    assert_eq!(status.last_failure, None);
}

/// Runs itself again with `RLIMIT_MEMLOCK` at three pages: one data page and its two guards, so
/// the one-page arena is secret where the kernel has `memfd_secret`.
///
/// Kernels with the CVE-2026-93243 fix check secret pages against the limit of the user, not
/// the process: every secret page the same user holds counts, and three pages leave no room
/// for another process's arena. So `.config/nextest.toml` runs this test alone. It still meets
/// other secret memory of the same user, from another program, or under `cargo test` from the
/// tests in this binary that keep secret key arenas; the check is then skipped, saying why
/// ([`secret_refused_per_user`]), or fails where `CRYPTHIX_REQUIRE_SECRETMEM=1` or where the
/// probe found a kernel that charges per process, which cannot refuse it.
#[test]
fn a_secret_arena_fits_a_limit_of_its_data_and_guard_pages() {
    in_child_knowing_accounting(
        "a_secret_arena_fits_a_limit_of_its_data_and_guard_pages",
        child_with_room_for_data_and_guards,
    );
}

#[expect(clippy::print_stderr, reason = "a skipped check says so")]
fn child_with_room_for_data_and_guards() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(3 * page).expect("three pages fit in u64"));
    let status = secure_mem::init(Config::default().with_pages_per_arena(1).with_max_pages(1))
        .expect("an arena");
    if secretmem_required() {
        assert_eq!(status.key_level, Some(Level::Secret), "{:?}", status.reason);
    }
    if status.key_level != Some(Level::Secret) {
        if secret_refused_per_user(&status) {
            return;
        }
        assert_eq!(status.key_level, Some(Level::Locked));
        assert_eq!(status.reason, Some(Fallback::SecretUnavailable));
        eprintln!("memfd_secret is not available here; the secret check is skipped");
        return;
    }
    assert_eq!(status.reason, None);
    let key = SealKey::random().expect("a slot in the secret arena");
    assert_eq!(key.level(), Level::Secret);
}

/// Whether `status`, of a fresh key pool in a process whose lock budget had room for its secret
/// arena, data and guard pages, shows the arena refused by a kernel that charges secret memory
/// per user: `Locked` for `LockLimit`. Kernels before the CVE-2026-93243 fix check a secret
/// mapping against this process's own limit, which had room, so only a kernel that also counts
/// the user's other secret pages (other processes', or this test binary's own under
/// `cargo test`) refuses here. The probe's [`accounting`] says which kind this kernel is, so on
/// a per-process kernel such a refusal fails the test instead of passing as a skip. On a
/// per-user kernel the secret check is skipped, saying so; where `CRYPTHIX_REQUIRE_SECRETMEM=1`
/// it fails instead, since a run that requires secret memory must leave the limit to the test
/// (`.config/nextest.toml` runs such tests alone).
#[expect(clippy::print_stderr, reason = "a skipped check says so")]
fn secret_refused_per_user(status: &secure_mem::Status) -> bool {
    let refused =
        status.key_level == Some(Level::Locked) && status.reason == Some(Fallback::LockLimit);
    if refused {
        assert_eq!(
            accounting(),
            Accounting::PerUser,
            "a kernel that charges secret memory per process refused a secret arena within this \
             process's limit: {status:?}"
        );
        assert!(
            !secretmem_required(),
            "the kernel charges secret memory per user and other secret memory of this user \
             filled the limit: {status:?}"
        );
        eprintln!(
            "the kernel charges secret memory per user and this user's other secret memory \
             fills the limit; the secret check is skipped"
        );
    }
    refused
}

/// Runs itself again, knowing the kernel's accounting, with a holder process of this user
/// keeping [`HELD_PAGES`] secret pages, then lowers `RLIMIT_MEMLOCK` to three pages: room in the
/// lock budget for a one-page secret arena and its guards. A kernel that charges secret memory
/// per process gives the arena secret memory. A kernel with the CVE-2026-93243 fix counts the
/// holder's pages too and refuses the arena's page when it is faulted in: the raw `getrandom`
/// fault-in turns that refusal into `EFAULT` rather than a `SIGBUS` that would kill the child,
/// and the arena falls back to `Locked`, with `LockLimit` as the reason. Either way the key
/// works.
///
/// The holder's secret memory could refuse other tests on a per-user kernel, so
/// `.config/nextest.toml` runs this test alone. `cargo xtask kernel-test` runs it on kernels of
/// both kinds.
#[test]
fn a_secret_arena_refused_at_fault_time_falls_back_to_locked() {
    in_child_knowing_accounting(
        "a_secret_arena_refused_at_fault_time_falls_back_to_locked",
        child_beside_a_holder_of_secret_memory,
    );
}

#[expect(clippy::print_stderr, reason = "a skipped check says so")]
fn child_beside_a_holder_of_secret_memory() {
    let Some(holder) = Holder::hold(HELD_PAGES) else {
        assert!(
            !secretmem_required(),
            "CRYPTHIX_REQUIRE_SECRETMEM=1, but the kernel gives no secret memory"
        );
        eprintln!("memfd_secret is not available here; the fault-time check is skipped");
        return;
    };
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(3 * page).expect("three pages fit in u64"));
    let status = secure_mem::init(Config::default().with_pages_per_arena(1).with_max_pages(1))
        .expect("an arena");
    let expected = match accounting() {
        Accounting::PerProcess => (Some(Level::Secret), None),
        Accounting::PerUser => (Some(Level::Locked), Some(Fallback::LockLimit)),
        Accounting::Unavailable => panic!("the holder got secret memory, so the probe did too"),
    };
    assert_eq!((status.key_level, status.reason), expected, "{status:?}");
    assert_eq!(status.last_failure, None);
    let key = SealKey::random().expect("a slot in the arena");
    assert_eq!(Some(key.level()), status.key_level);
    let aad = Aad::new(AadLabel::BlobData).field(&[9; 16]);
    let sealed = cx_aead::seal(&key, &aad, b"beside the holder", NonceKind::Hedged).expect("seals");
    let opened = cx_aead::open(&key, &aad, &sealed).expect("opens");
    assert_eq!(opened.as_slice(), b"beside the holder");
    drop(holder);
}

/// The `AUDIT_ARCH_*` value seccomp reports for this target's native system calls
/// (`include/uapi/linux/audit.h`): its ELF machine number with the 64-bit and little-endian
/// flags.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

/// Makes every later `memfd_secret` call of this process fail with `errno`, as a container
/// runtime's seccomp profile may, and checks that it does.
///
/// The filter is classic BPF over `struct seccomp_data` (seccomp(2)): it loads `arch` (offset
/// 4) and allows calls of any other architecture, then loads `nr` (offset 0) and returns
/// `SECCOMP_RET_ERRNO | errno` for `memfd_secret` and `SECCOMP_RET_ALLOW` for the rest.
/// `PR_SET_NO_NEW_PRIVS` first lets a process without `CAP_SYS_ADMIN` install it.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[expect(
    unsafe_code,
    reason = "prctl and a raw system call have no safe interface"
)]
fn deny_memfd_secret(errno: i32) {
    let code = |code: u32| u16::try_from(code).expect("BPF opcodes fit in 16 bits");
    let statement = |op: u32, k: u32| libc::sock_filter {
        code: code(op),
        jt: 0,
        jf: 0,
        k,
    };
    let jump_if_equal = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K),
        jt,
        jf,
        k,
    };
    let load_word = |offset: u32| statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset);
    let nr = u32::try_from(libc::SYS_memfd_secret).expect("system call numbers fit in u32");
    let errno_data = u32::try_from(errno).expect("an errno is positive") & libc::SECCOMP_RET_DATA;
    let mut filter = [
        load_word(4),
        jump_if_equal(AUDIT_ARCH, 0, 3),
        load_word(0),
        jump_if_equal(nr, 0, 1),
        statement(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_ERRNO | errno_data,
        ),
        statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).expect("six instructions"),
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integers only.
    let no_new_privs =
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1_u64, 0_u64, 0_u64, 0_u64) };
    assert_eq!(no_new_privs, 0, "PR_SET_NO_NEW_PRIVS");
    // SAFETY: `program` points at `filter`, both alive for the call, which copies them.
    let installed = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            u64::from(libc::SECCOMP_MODE_FILTER),
            &raw const program,
        )
    };
    assert_eq!(
        installed,
        0,
        "PR_SET_SECCOMP: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: memfd_secret takes one integer of flags; denied, it does nothing.
    let result = unsafe { libc::syscall(libc::SYS_memfd_secret, 0_i64) };
    assert_eq!(
        (result, std::io::Error::last_os_error().raw_os_error()),
        (-1, Some(errno)),
        "the filter denies memfd_secret"
    );
}

/// With `memfd_secret` denied by a seccomp filter with `errno`, keys fall back to locked memory
/// and `status` names the missing call as the reason.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn keys_are_locked_where_memfd_secret_is_denied(errno: i32) {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(16 * page).expect("16 pages fit in u64"));
    deny_memfd_secret(errno);
    let status = secure_mem::init(Config::default().with_pages_per_arena(1).with_max_pages(4))
        .expect("a locked arena");
    assert_eq!(status.key_level, Some(Level::Locked));
    assert_eq!(status.reason, Some(Fallback::SecretUnavailable));
    let key = SealKey::random().expect("a key");
    assert_eq!(key.level(), Level::Locked);
}

/// Runs itself again with `memfd_secret` failing with `ENOSYS`, as on a kernel without it.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn keys_are_locked_where_memfd_secret_is_missing() {
    in_child(
        "keys_are_locked_where_memfd_secret_is_missing",
        child_with_memfd_secret_missing,
    );
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn child_with_memfd_secret_missing() {
    keys_are_locked_where_memfd_secret_is_denied(libc::ENOSYS);
}

/// Runs itself again with `memfd_secret` failing with `EPERM`, as Docker's default seccomp
/// profile denies calls it does not list.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn keys_are_locked_where_memfd_secret_is_forbidden() {
    in_child(
        "keys_are_locked_where_memfd_secret_is_forbidden",
        child_with_memfd_secret_forbidden,
    );
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn child_with_memfd_secret_forbidden() {
    keys_are_locked_where_memfd_secret_is_denied(libc::EPERM);
}

/// Runs itself again with `memfd_secret` failing with `ENOSYS`: `init` with a minimum of
/// `Secret` fails, naming the locked arena it got instead and why.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn a_minimum_of_secret_fails_where_memfd_secret_is_missing() {
    in_child(
        "a_minimum_of_secret_fails_where_memfd_secret_is_missing",
        child_requiring_secret_without_it,
    );
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn child_requiring_secret_without_it() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(16 * page).expect("16 pages fit in u64"));
    deny_memfd_secret(libc::ENOSYS);
    let below = MemError::BelowMinimum {
        got: Level::Locked,
        want: Level::Secret,
    };
    let config = Config::default()
        .with_minimum(Level::Secret)
        .with_pages_per_arena(1)
        .with_max_pages(4);
    assert_eq!(secure_mem::init(config).err(), Some(below));
    let status = secure_mem::status();
    assert_eq!(status.reason, Some(Fallback::SecretUnavailable));
    assert_eq!(status.last_failure, Some(below));
    assert_eq!(SealKey::random().err(), Some(KeyError::Memory(below)));
}

/// Runs itself again with a one-page pool: `open_key` frees the slot it took whenever the wrap
/// does not give a key (a changed tag, an all-zero key, data sealed under a data label), and an
/// unwrapped key takes one. With every slot taken, a wrap of the wrong length or under a data
/// label is still the format error, checked before the pool, while a wrap that would open, or a
/// changed one, gets `PoolExhausted`: the slot comes before the wrap is opened. Needs
/// `seal_with_nonce` (`vectors`) to seal an all-zero key, which `seal_key` cannot.
#[cfg(feature = "vectors")]
#[test]
fn open_key_frees_its_slot_on_every_error_and_checks_the_format_first() {
    in_child(
        "open_key_frees_its_slot_on_every_error_and_checks_the_format_first",
        child_unwrapping_into_a_one_page_pool,
    );
}

#[cfg(feature = "vectors")]
fn child_unwrapping_into_a_one_page_pool() {
    let per_page = rustix::param::page_size() / 32;
    secure_mem::init(Config::default().with_pages_per_arena(1).with_max_pages(1))
        .expect("a one-page pool");
    let wrapping = SealKey::random().expect("a key");
    let aad = Aad::new(AadLabel::DekWrap).field(&[9; 16]);
    let data_aad = Aad::new(AadLabel::BlobData).field(&[9; 16]);
    let wrap =
        cx_aead::seal_key(&wrapping, &aad, &KdfKey::random().expect("a key")).expect("wraps");
    let mut tampered = wrap.clone();
    tampered[cx_aead::WRAPPED_KEY_LEN - 1] ^= 1;
    let zero = cx_aead::seal_with_nonce(&wrapping, &aad, &[0; 32], &[5; 24]);
    let data = cx_aead::seal_with_nonce(&wrapping, &data_aad, &[7; 32], &[6; 24]);
    let used = secure_mem::status().key_slots_used;
    assert_eq!(used, 1, "the wrapping key; the wrapped one is dropped");
    for (input, aad, error) in [
        (&tampered, &aad, FormatError::Decrypt),
        (&zero, &aad, FormatError::ZeroValue),
        (&data, &data_aad, FormatError::Decrypt),
    ] {
        assert_eq!(
            cx_aead::open_key::<KdfKey>(&wrapping, aad, input).err(),
            Some(KeyError::Format(error))
        );
        assert_eq!(
            secure_mem::status().key_slots_used,
            used,
            "{error:?}: the slot was freed"
        );
    }
    let unwrapped: KdfKey = cx_aead::open_key(&wrapping, &aad, &wrap).expect("opens");
    assert_eq!(secure_mem::status().key_slots_used, used + 1);
    let rest: Vec<SealKey> = (used + 1..per_page)
        .map(|_| SealKey::random().expect("a free slot"))
        .collect();
    assert_eq!(
        secure_mem::status().key_slots_used,
        per_page,
        "the pool is full"
    );
    let mut long = wrap.clone();
    long.push(0);
    for (input, aad, error) in [
        (
            &wrap[..cx_aead::WRAPPED_KEY_LEN - 1],
            &aad,
            FormatError::Truncated,
        ),
        (&long[..], &aad, FormatError::TrailingBytes),
        (&data[..], &data_aad, FormatError::Decrypt),
    ] {
        assert_eq!(
            cx_aead::open_key::<KdfKey>(&wrapping, aad, input).err(),
            Some(KeyError::Format(error)),
            "checked before the pool"
        );
    }
    for input in [&wrap, &tampered] {
        assert_eq!(
            cx_aead::open_key::<KdfKey>(&wrapping, &aad, input).err(),
            Some(KeyError::Memory(MemError::PoolExhausted))
        );
    }
    drop((unwrapped, rest));
}

/// Runs itself again with `RLIMIT_MEMLOCK` at 16 pages and a one-page pool, filled: `kdf` and
/// Argon2id fail for want of a slot for their key, and Argon2id fails before it maps its
/// 256 MiB of blocks, which could not be locked under that limit and would leave `status`
/// reporting a buffer weaker than the passphrase's locked one.
#[test]
fn derivations_into_a_full_pool_fail_before_any_work() {
    in_child(
        "derivations_into_a_full_pool_fail_before_any_work",
        child_deriving_into_a_full_pool,
    );
}

fn child_deriving_into_a_full_pool() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(16 * page).expect("16 pages fit in u64"));
    secure_mem::init(Config::default().with_pages_per_arena(1).with_max_pages(1))
        .expect("a one-page pool");
    let passphrase = Passphrase::new("correct horse battery staple".to_owned()).expect("a buffer");
    assert_eq!(secure_mem::status().buffer_level, Some(Level::Locked));
    let ikm = KdfKey::random().expect("a key");
    let rest: Vec<SealKey> = (1..page / 32)
        .map(|_| SealKey::random().expect("a free slot"))
        .collect();
    let context = KdfContext::new().field(&[1; 16]);
    assert_eq!(
        kdf::kdf(&ikm, None, SealKeyLabel::DekWrap, &context).err(),
        Some(MemError::PoolExhausted)
    );
    let params =
        KdfParams::new(KdfParams::MIN_M_COST, KdfParams::MIN_T_COST, 1).expect("at the floor");
    assert_eq!(
        argon2id::derive(&passphrase, &[7; 32], &params).err(),
        Some(DeriveError::KeyMemory(MemError::PoolExhausted))
    );
    let status = secure_mem::status();
    assert_eq!(
        status.buffer_level,
        Some(Level::Locked),
        "no blocks were mapped"
    );
    assert_eq!(status.key_slots_used, page / 32);
    drop((ikm, rest));
}

/// Runs itself again with the address space capped as in
/// [`a_buffer_the_kernel_will_not_map_is_refused_not_put_on_the_heap`]: Argon2id takes its key's
/// slot from the existing arena, then fails to map its blocks with `ArgonMemory`, and frees the
/// slot again.
#[test]
fn argon2_without_memory_for_its_blocks_frees_the_key_slot() {
    in_child(
        "argon2_without_memory_for_its_blocks_frees_the_key_slot",
        child_deriving_with_no_address_space_left,
    );
}

fn child_deriving_with_no_address_space_left() {
    let passphrase = Passphrase::new("correct horse battery staple".to_owned()).expect("a buffer");
    let key = SealKey::random().expect("a key, which maps the first arena");
    let used = secure_mem::status().key_slots_used;
    let params =
        KdfParams::new(KdfParams::MIN_M_COST, KdfParams::MIN_T_COST, 1).expect("at the floor");
    let unlimited = cap_address_space();
    let derived = argon2id::derive(&passphrase, &[7; 32], &params).err();
    let after = secure_mem::status().key_slots_used;
    restore_address_space(unlimited);
    assert_eq!(derived, Some(DeriveError::ArgonMemory));
    assert_eq!(after, used, "the derived key's slot was freed");
    drop(key);
}

/// Runs itself again with the address space capped so the kernel maps nothing, and a minimum
/// of `Heap`: every mapped level is refused, so keys go on the heap, `status` says the kernel
/// refused, and they seal. Opening needs a plaintext buffer, which on Linux is never put on the
/// heap, so it fails with the memory error until the kernel maps again; then the heap key opens
/// what it sealed.
#[test]
fn keys_go_on_the_heap_when_the_kernel_maps_nothing_and_the_minimum_allows() {
    in_child(
        "keys_go_on_the_heap_when_the_kernel_maps_nothing_and_the_minimum_allows",
        child_with_keys_on_the_heap,
    );
}

fn child_with_keys_on_the_heap() {
    // `status` sets up the fork generation's marker page while mappings still work, and no
    // pool, so `init` may follow.
    assert!(!secure_mem::status().initialised);
    let aad = Aad::new(AadLabel::BlobData).field(&[3; 16]);
    let unlimited = cap_address_space();
    let config = Config::default()
        .with_minimum(Level::Heap)
        .with_pages_per_arena(1);
    let status = secure_mem::init(config).expect("the heap is always available");
    let key = SealKey::random().expect("a slot on the heap");
    let sealed = cx_aead::seal(&key, &aad, b"on the heap", NonceKind::Hedged).expect("seals");
    let opened = cx_aead::open(&key, &aad, &sealed).map(|buf| buf.level());
    restore_address_space(unlimited);
    assert_eq!(status.key_level, Some(Level::Heap));
    assert_eq!(status.reason, Some(Fallback::KernelRefused));
    assert_eq!(status.last_failure, None);
    assert_eq!(key.level(), Level::Heap);
    assert_eq!(
        opened,
        Err(OpenError::Memory(MemError::MapFailed)),
        "no plaintext buffer on the heap"
    );
    assert_eq!(
        cx_aead::open(&key, &aad, &sealed)
            .expect("opens with room again")
            .as_slice(),
        b"on the heap"
    );
}

/// Runs itself again, so no pool exists yet, with `RLIMIT_MEMLOCK` at 16 pages, below the
/// default pool's reserve, and makes a passphrase before `init`: its buffer sets up the default
/// pool first, so it locks none of the default's reserve (here the whole limit) and maps no key
/// arena, and a stricter `init` after it fails with `AlreadyInitialised` instead of carrying
/// on with the default's minimum.
#[test]
fn a_buffer_before_init_sets_up_the_default_pool_and_init_then_fails() {
    in_child(
        "a_buffer_before_init_sets_up_the_default_pool_and_init_then_fails",
        child_with_a_passphrase_before_init,
    );
}

fn child_with_a_passphrase_before_init() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(16 * page).expect("16 pages fit in u64"));
    let passphrase = Passphrase::new("correct horse battery staple".to_owned()).expect("a buffer");
    let status = secure_mem::status();
    assert!(status.initialised, "the first buffer set up the pool");
    assert_eq!(status.minimum, Config::default().minimum());
    assert_eq!(
        (status.key_level, status.key_slots_total),
        (None, 0),
        "a buffer maps no key arena"
    );
    assert_eq!(
        (status.buffer_level, status.buffer_reason),
        (Some(Level::DumpExcluded), Some(Fallback::LockLimit)),
        "the default reserve passes the limit, so the buffer locks none of it"
    );
    let stricter = Config::default()
        .with_minimum(Level::Locked)
        .with_pages_per_arena(1)
        .with_max_pages(1);
    assert_eq!(
        secure_mem::init(stricter).err(),
        Some(MemError::AlreadyInitialised),
        "too late, and said so"
    );
    let after = secure_mem::status();
    assert_eq!(
        after.minimum,
        Config::default().minimum(),
        "the default pool stays"
    );
    assert_eq!(
        after.last_failure, None,
        "the refused config was never tried"
    );
    let key = SealKey::random().expect("a key in the default pool");
    assert!(
        key.level() >= Level::Locked,
        "the default pool's keys may lock the whole limit: {:?}",
        secure_mem::status()
    );
    drop(passphrase);
}

/// Runs itself again, so no pool exists yet: even an empty buffer, which maps nothing, sets up
/// the default pool, so the rule is "the first buffer" whatever its length.
#[test]
fn an_empty_buffer_sets_up_the_default_pool_too() {
    in_child(
        "an_empty_buffer_sets_up_the_default_pool_too",
        child_with_an_empty_buffer_before_init,
    );
}

fn child_with_an_empty_buffer_before_init() {
    assert!(!secure_mem::status().initialised);
    let empty = SecretBuf::try_zeroed(0).expect("an empty buffer");
    assert_eq!(empty.level(), None, "nothing mapped");
    assert!(secure_mem::status().initialised);
    assert_eq!(
        secure_mem::init(Config::default().with_minimum(Level::Heap)).err(),
        Some(MemError::AlreadyInitialised)
    );
}

/// Runs itself again with a pool of one-page arenas whose reserve (each page and its two guard
/// pages) is the whole `RLIMIT_MEMLOCK`, set by `init` before any buffer. The first arena uses
/// only 3 pages of it, so the kernel would lock a buffer in the rest, but buffers get none of
/// the reserve: a buffer is left out of core dumps, and every arena the pool may add still
/// locks. Where the hard limit allows, the reserve is 420 pages, more than the default pool's
/// 384, so buffers kept only to the default's reserve would lock here; below that the check is
/// the same with a smaller pool, which a default reserve would cover too, and it says so.
///
/// With up to 140 arenas of secret memory, which patched kernels charge per user, it runs alone
/// (`.config/nextest.toml`); an arena refused secret memory for other processes of the user is
/// locked instead, which this test accepts unless `CRYPTHIX_REQUIRE_SECRETMEM=1`, where every
/// arena must be secret on kernels of either kind.
#[test]
fn a_reserve_larger_than_the_default_is_kept_from_buffers() {
    in_child(
        "a_reserve_larger_than_the_default_is_kept_from_buffers",
        child_with_a_reserve_of_the_whole_limit,
    );
}

#[expect(
    clippy::print_stderr,
    reason = "a check the limit does not allow says so"
)]
fn child_with_a_reserve_of_the_whole_limit() {
    use rustix::process::{self, Resource};

    const ARENAS: usize = 140;
    let page = rustix::param::page_size();
    let default = Config::default();
    let default_reserve =
        default.max_pages() + 2 * (default.max_pages() / default.pages_per_arena().get());
    assert!(3 * ARENAS > default_reserve, "past the default reserve");
    let hard_pages = process::getrlimit(Resource::Memlock)
        .maximum
        .map_or(usize::MAX, |bytes| {
            usize::try_from(bytes).unwrap_or(usize::MAX) / page
        });
    let arenas = ARENAS.min(hard_pages / 3);
    if arenas < ARENAS {
        eprintln!(
            "RLIMIT_MEMLOCK's hard limit is {hard_pages} pages, below {}; checking a reserve of \
             {} pages, which does not pass the default reserve of {default_reserve}",
            3 * ARENAS,
            3 * arenas
        );
    }
    assert!(arenas >= 1, "the hard limit has room for one arena");
    set_memlock_limit(u64::try_from(3 * arenas * page).expect("the limit fits in u64"));
    let config = Config::default()
        .with_minimum(Level::Locked)
        .with_pages_per_arena(1)
        .with_max_pages(arenas);
    let status = secure_mem::init(config).expect("the first arena fits the limit");
    let per_arena = status.key_slots_total;
    let buf = SecretBuf::try_zeroed(1).expect("memory for a buffer");
    assert_eq!(
        buf.level(),
        Some(Level::DumpExcluded),
        "the kernel has room, but the reserve keeps it for keys"
    );
    assert_eq!(
        secure_mem::status().buffer_reason,
        Some(Fallback::LockLimit)
    );
    let keys: Vec<SealKey> = (0..arenas * per_arena)
        .map(|_| SealKey::random().expect("every arena the pool may add locks"))
        .collect();
    let status = secure_mem::status();
    assert_eq!(status.key_slots_total, arenas * per_arena, "every arena");
    assert!(status.key_level >= Some(Level::Locked), "{status:?}");
    if secretmem_required() {
        // Per process the limit is exactly the arenas' data and guard pages; per user it is
        // three times their faulted-in data pages, with nothing else running.
        assert_eq!(status.key_level, Some(Level::Secret), "{status:?}");
    }
    assert_eq!(status.last_failure, None);
    drop((keys, buf));
}

/// Runs itself again, so no pool exists yet: `status` before anything reports no pool, the
/// default minimum and nothing else, and sets up none, so an `init` with a stricter minimum
/// after it succeeds, and `status` then reports that minimum.
#[test]
fn status_sets_up_no_pool_so_init_may_follow() {
    in_child(
        "status_sets_up_no_pool_so_init_may_follow",
        child_looking_before_init,
    );
}

fn child_looking_before_init() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(16 * page).expect("16 pages fit in u64"));
    let before = secure_mem::status();
    assert!(!before.initialised);
    assert_eq!(before.minimum, Config::default().minimum());
    assert_eq!(
        (
            before.key_level,
            before.key_slots_used,
            before.key_slots_total
        ),
        (None, 0, 0)
    );
    assert_eq!(
        (
            before.buffer_level,
            before.buffer_reason,
            before.reason,
            before.last_failure
        ),
        (None, None, None, None)
    );
    assert_eq!(
        secure_mem::status(),
        before,
        "a second look sets up nothing"
    );
    let stricter = Config::default()
        .with_minimum(Level::Locked)
        .with_pages_per_arena(1)
        .with_max_pages(1);
    let status = secure_mem::init(stricter).expect("status set up no pool, so init still may");
    assert!(status.initialised);
    assert_eq!(status.minimum, Level::Locked);
    assert!(status.key_level >= Some(Level::Locked), "{status:?}");
    let after = secure_mem::status();
    assert_eq!(after.minimum, Level::Locked, "the configured minimum");
    assert_eq!(after.key_slots_total, status.key_slots_total);
}

/// Runs itself again, so forking is safe: after the parent's `init` with a minimum of
/// `Locked`, a forked child's `status` reports no pool and the default minimum, not the
/// parent's, and sets up none, so the child's own `init` succeeds with another minimum; the
/// parent's pool is unchanged.
#[test]
fn status_in_a_forked_child_shows_no_pool_and_sets_up_none() {
    in_child(
        "status_in_a_forked_child_shows_no_pool_and_sets_up_none",
        fork_and_look,
    );
}

fn fork_and_look() {
    let page = rustix::param::page_size();
    set_memlock_limit(u64::try_from(16 * page).expect("16 pages fit in u64"));
    let config = Config::default()
        .with_minimum(Level::Locked)
        .with_pages_per_arena(1)
        .with_max_pages(1);
    secure_mem::init(config).expect("one page for keys");
    let key = SealKey::random().expect("a key");
    let Some(child) = fork() else {
        run_child(|| {
            let status = secure_mem::status();
            assert!(!status.initialised, "the parent's pool is not the child's");
            assert_eq!(status.minimum, Config::default().minimum());
            assert_eq!(
                (
                    status.key_level,
                    status.key_slots_used,
                    status.key_slots_total
                ),
                (None, 0, 0)
            );
            assert_eq!(secure_mem::status(), status, "and looking set up none");
            let own = secure_mem::init(config.with_minimum(Level::Heap))
                .expect("the child's status set up no pool");
            assert_eq!(own.minimum, Level::Heap);
            assert!(own.initialised);
        });
    };
    let status = wait(child);
    assert_eq!(
        status.exit_status(),
        Some(0),
        "the forked child: {status:?}"
    );
    let parent = secure_mem::status();
    assert_eq!(parent.minimum, Level::Locked);
    assert_eq!(parent.key_slots_used, 1);
    drop(key);
}

/// Runs itself again, so forking is safe, and forks a child for each of several rounds, in
/// which threads released together each call `init` (with a minimum of `Heap`, unlike the
/// default) and make a key, in three orders: `init` first, the key first, or a plaintext buffer
/// first. Exactly one pool is installed: at most one `init` succeeds and every other is
/// `AlreadyInitialised`, the pool's minimum is the successful `init`'s, or the default's if a
/// key or buffer installed the pool first, and every key is made, in that one pool.
#[test]
fn init_racing_the_first_key_installs_one_pool() {
    in_child(
        "init_racing_the_first_key_installs_one_pool",
        race_init_against_the_first_key,
    );
}

fn race_init_against_the_first_key() {
    const ROUNDS: usize = 16;
    for round in 0..ROUNDS {
        let Some(child) = fork() else {
            run_child(race_once);
        };
        let status = wait(child);
        assert_eq!(status.exit_status(), Some(0), "round {round}: {status:?}");
    }
}

/// One round of [`race_init_against_the_first_key`], in a forked child with no pool of its own
/// yet.
fn race_once() {
    const THREADS: usize = 9;
    let config = Config::default().with_minimum(Level::Heap);
    let start = std::sync::Barrier::new(THREADS);
    let results: Vec<(
        Result<secure_mem::Status, MemError>,
        Result<SealKey, KeyError>,
    )> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|thread| {
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    match thread % 3 {
                        0 => {
                            let init = secure_mem::init(config);
                            (init, SealKey::random())
                        }
                        1 => {
                            let key = SealKey::random();
                            (secure_mem::init(config), key)
                        }
                        _ => {
                            let buf = SecretBuf::try_zeroed(1).expect("memory for a buffer");
                            let init = secure_mem::init(config);
                            drop(buf);
                            (init, SealKey::random())
                        }
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the thread ran"))
            .collect()
    });
    let mut installed = 0;
    for (init, key) in &results {
        match init {
            Ok(status) => {
                installed += 1;
                assert_eq!(status.minimum, Level::Heap);
            }
            Err(error) => assert_eq!(*error, MemError::AlreadyInitialised),
        }
        assert!(key.is_ok(), "{key:?}");
    }
    assert!(installed <= 1, "{installed} calls of init succeeded");
    let status = secure_mem::status();
    let minimum = if installed == 1 {
        Level::Heap
    } else {
        Config::default().minimum()
    };
    assert_eq!(status.minimum, minimum, "the one pool");
    assert_eq!(status.key_slots_used, THREADS, "every key is in it");
}
