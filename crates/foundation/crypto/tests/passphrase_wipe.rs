//! `Passphrase::new` wipes the `String` it is given before freeing it (O1), and also when it
//! cannot copy it into protected memory.
//!
//! Reading memory after it is freed is undefined behaviour, so this test binary's allocator
//! looks instead: it checks the one watched block as `dealloc` hands it over, while it is still
//! allocated, then frees it.
#![expect(
    unsafe_code,
    reason = "a global allocator, which reads a block before passing it on to be freed"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use crypthix_crypto::key::Passphrase;

/// The address of the block to check when it is freed; 0 for none.
static WATCHED: AtomicUsize = AtomicUsize::new(0);

/// What the check found: [`UNSEEN`] until the watched block is freed.
static FOUND: AtomicU8 = AtomicU8::new(UNSEEN);
const UNSEEN: u8 = 0;
const WIPED: u8 = 1;
const NOT_WIPED: u8 = 2;

/// [`System`], checking the [`WATCHED`] block when it is freed.
struct Checking;

// SAFETY: every call is passed on to `System` unchanged; `dealloc` only reads the block first.
unsafe impl GlobalAlloc for Checking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's guarantees for `alloc`, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let watched = WATCHED.compare_exchange(ptr.addr(), 0, Ordering::AcqRel, Ordering::Acquire);
        if watched.is_ok() {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until `System.dealloc`
            // below. The test makes it a `String` whose length equals its capacity, so every
            // byte was initialised, and the caller has given up its ownership.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            let found = if bytes.iter().all(|byte| *byte == 0) {
                WIPED
            } else {
                NOT_WIPED
            };
            FOUND.store(found, Ordering::Release);
        }
        // SAFETY: the caller's guarantees for `dealloc`, passed on.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Checking = Checking;

/// A passphrase whose block every byte of is initialised, watched until it is freed.
fn watched_text() -> String {
    let secret = "correct horse battery staple";
    let mut text = String::with_capacity(secret.len());
    text.push_str(secret);
    assert_eq!(
        text.capacity(),
        text.len(),
        "every byte of the block is initialised"
    );
    WATCHED.store(text.as_ptr().addr(), Ordering::Release);
    text
}

/// Checks the watched block was freed, and wiped first.
fn assert_wiped() {
    assert_eq!(
        FOUND.load(Ordering::Acquire),
        WIPED,
        "the string was freed by `new`, and wiped first ({UNSEEN}: not freed)"
    );
}

#[test]
fn the_source_string_is_wiped_before_it_is_freed() {
    let passphrase = Passphrase::new(watched_text()).expect("a buffer");
    assert_wiped();
    assert_eq!(format!("{passphrase:?}"), "Passphrase(..)");
}

/// Runs itself again, alone, with the address space capped two pages above what it uses, so no
/// buffer can be mapped: `new` fails, and has wiped the string all the same.
#[cfg(all(target_os = "linux", not(miri)))]
#[test]
fn the_source_string_is_wiped_when_no_buffer_can_be_had() {
    use std::process::Command;

    const CHILD: &str = "CRYPTHIX_TEST_CHILD";
    const NAME: &str = "the_source_string_is_wiped_when_no_buffer_can_be_had";
    if std::env::var_os(CHILD).is_some() {
        refuse_a_watched_passphrase();
        return;
    }
    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args([NAME, "--exact", "--test-threads=1"])
        .env(CHILD, NAME)
        .output()
        .expect("the test binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed;"),
        "child failed: {:?}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The child of [`the_source_string_is_wiped_when_no_buffer_can_be_had`].
#[cfg(all(target_os = "linux", not(miri)))]
fn refuse_a_watched_passphrase() {
    use crypthix_crypto::secure_mem::{MemError, SecretBuf};
    use rustix::process::{self, Resource};

    // Sets up the fork marker page that the first buffer maps, while there is room for it.
    drop(SecretBuf::try_copy_from(b"x").expect("memory for a buffer"));
    let text = watched_text();
    // Leaves free heap memory behind, so a heap allocation needs no new mapping.
    drop(std::hint::black_box(Vec::<u8>::with_capacity(64 * 1024)));
    let status = std::fs::read_to_string("/proc/self/status").expect("procfs is mounted");
    let used = status
        .lines()
        .find_map(|line| line.strip_prefix("VmSize:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .expect("a VmSize line in kB")
        * 1024;
    let page = u64::try_from(rustix::param::page_size()).expect("a page size fits in u64");
    let unlimited = process::getrlimit(Resource::As);
    let mut capped = unlimited;
    capped.current = Some(used + 2 * page);
    process::setrlimit(Resource::As, capped).expect("lowering a soft limit is always allowed");
    let refused = Passphrase::new(text).err();
    process::setrlimit(Resource::As, unlimited).expect("the hard limit was not lowered");
    assert_eq!(refused, Some(MemError::MapFailed));
    assert_wiped();
}
