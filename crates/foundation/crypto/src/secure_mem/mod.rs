//! Protected memory for keys and plaintext (O1, T-31).
//!
//! Every key of this crate lives in a 32-byte slot of the process-wide key pool; plaintext lives
//! in [`SecretBuf`]s. Both are wiped before they are freed and, on Linux, left out of core dumps
//! and of forked children and placed at the strongest [`Level`] the system gives:
//!
//! 1. [`Level::Secret`]: `memfd_secret(2)` pages, for keys only (see
//!    [why not plaintext](#why-plaintext-stays-out-of-secret-memory)). The kernel removes them
//!    from its own map and refuses them to `PTRACE_PEEKDATA`, `process_vm_readv` and
//!    `/proc/<pid>/mem`; a process allowed to `ptrace` this one can still inject code that
//!    reads them.
//! 2. [`Level::Locked`]: `mlock`ed anonymous pages, which are never swapped. Plaintext buffers
//!    stop here.
//! 3. [`Level::DumpExcluded`]: when `RLIMIT_MEMLOCK` is too low to lock. On Linux this is the
//!    floor for plaintext: a buffer the kernel will not map at all is refused, never put on
//!    the heap.
//!
//! All of this is Linux only. On other systems (Windows and macOS until A11 and A12 port it) and
//! under Miri, keys and buffers are plain [`Level::Heap`] memory: wiped before it is freed, but
//! with no guard pages, no locking, and no exclusion from core dumps or forked children.
//! [`status`](fn@status) reports [`Fallback::Platform`] there, and an [`init`] whose minimum is
//! above `Heap` fails with [`MemError::BelowMinimum`].
//!
//! Keys and buffers lock separate shares of `RLIMIT_MEMLOCK`: the key pool keeps enough for
//! every page [`Config::with_max_pages`] lets it map, and buffers lock only what is left, so open
//! plaintext never pushes a key arena down a level. The pool, and with it that reserve, is set
//! up before anything locks: by [`init`], or with [`Config::default`] by the first key or the
//! first buffer, after which `init` fails with [`MemError::AlreadyInitialised`] instead of
//! keeping less than it asks for; [`status`](fn@status) never sets it up. These shares only save doomed system calls; the kernel's accounting
//! decides, and a mapping it refuses falls back a level. Secret pages are faulted in through the
//! raw `getrandom(2)` system call, so a kernel that will not charge one more page fails that
//! call rather than raise `SIGBUS` at a later write (the fault handler, `secretmem_fault` in
//! `mm/secretmem.c`, returns `VM_FAULT_SIGBUS` past the limit).
//!
//! The key pool is process-wide, and so is the state that goes with it: on Linux the lock budget's
//! counts of locked bytes (the share kept for keys is read from the pool), the weakest level a buffer got and why the
//! latest fell below locked, for [`status`](fn@status), and the fork generation with its marker
//! page. These atomics are the crate's only global state (backlog rule 6).
//!
//! An app calls [`init`] once at startup, before its first key or plaintext buffer, with the
//! weakest level it accepts, and shows [`status`](fn@status), which may come before `init`. While a secret page exists the kernel refuses to hibernate, and key
//! arenas are never unmapped, so once a process has made a key in secret memory it blocks
//! hibernation until it exits.
//!
//! # Fork
//!
//! On Linux, keys and buffers made before `fork` cannot be used in a child forked without
//! `exec`: reading one panics. Their mappings are not copied into the child, so dropping one
//! there leaves the address alone; a key on the heap (where the minimum is [`Level::Heap`] and
//! nothing else was mapped) is the child's own copy, wiped when it is dropped. The child tells
//! what it inherited by a fork generation kept in a `MADV_WIPEONFORK` page, not by its process
//! id, which a PID namespace or reuse can repeat. It starts with an empty key pool, lock budget,
//! buffer level and buffer reason of its own, so it may call [`init`], create new keys and lock
//! what its own `RLIMIT_MEMLOCK` allows. Apps that fork should `exec`, or create the keys the
//! child needs after the fork.
//!
//! Elsewhere, and under Miri, all memory is heap and a forked child holds its own
//! copy-on-write copy of every key and buffer, which it may use and wipes when it drops it.
//!
//! # Why plaintext stays out of secret memory
//!
//! This is the one statement of the reasons; other docs point here. Plaintext buffers stop at
//! [`Level::Locked`] because:
//!
//! - The kernel refuses secret pages, with `EFAULT`, to every path that pins user pages
//!   (`get_user_pages`; `check_vma_flags` in `mm/gup.c`), so `O_DIRECT` I/O, `vmsplice` and
//!   FUSE's zero-copy `splice` of a protected path (A1) would fail on them.
//! - Each secret page is removed from the kernel's direct map, which splits its large pages.
//! - Each secret page counts against `RLIMIT_MEMLOCK`, too costly for large buffers.
//!
//! Copying system calls such as `read`, `write` and `getrandom` do reach secret pages, and key
//! creation relies on that: every page of a secret mapping is faulted in by the raw `getrandom`
//! system call, and keys are filled by `getrandom` in place. An `EFAULT` from that fault-in is
//! reported as [`Fallback::LockLimit`], since a page past a per-user limit is its usual cause.
//! So a kernel that refused copying calls too would make every key arena fall back a level,
//! never below the app's minimum, and [`status`](fn@status) would wrongly blame the lock limit.
//!
//! # What this does not cover
//!
//! The final location of every key type and buffer is wiped when it is dropped
//! (`ZeroizeOnDrop` or a wipe in `Drop`), but copies left behind by moves and by the compiler
//! spilling registers to the stack are short-lived and not reliably wiped. The working state of
//! the cipher and MAC code is ordinary stack memory, not protected memory, and is wiped when it
//! is dropped: CX-AEAD's subkey `K_enc` in the `XChaCha20Poly1305` state for a whole seal or
//! open, `K_n` in the keyed BLAKE3 state while a seal hashes its plaintext into the nonce, the
//! HKDF PRK in its HMAC state for each derivation, and the Ed25519 key expanded for each
//! signature. Hibernation images of locked pages are not covered either.
//!
//! # Testing
//!
//! Miri runs the unit tests on the [`Level::Heap`] backing, so it checks the slot and arena
//! pointer logic, the slices over a buffer, the open paths and the wipes. The `mmap`,
//! `mprotect`, `mlock` and `memfd_secret` code is compiled out there; the native Linux tests,
//! `tests/secure_mem_linux.rs` among them, cover it.
//!
//! The host and CI runner kernels predate the CVE-2026-93243 fix, so the per-user accounting of
//! patched kernels, and the fault-time refusal that the `getrandom` fault-in turns into
//! [`Fallback::LockLimit`], are checked by the `kernel-test` CI job
//! (`.github/workflows/kernel-test.yml`, `cargo xtask kernel-test`): it boots a kernel with the
//! fix and one without it and runs the tests in each, after a probe test that asks the kernel
//! which accounting it uses and must find the one each kernel is pinned for.

mod arena;
mod buffer_level;
mod config;
mod fallback;
mod fork_generation;
mod global;
mod key_pool;
mod key_slot;
mod level;
mod lock_budget;
mod mem_error;
#[cfg(all(target_os = "linux", not(miri)))]
mod memfd_secret;
mod region;
mod secret_buf;
mod secret_vec;
mod status;

pub use config::Config;
pub use fallback::Fallback;
pub(crate) use global::take_key_slot;
pub use global::{init, status};
pub(crate) use key_slot::KeySlot;
pub use level::Level;
pub use mem_error::MemError;
pub use secret_buf::SecretBuf;
pub(crate) use secret_vec::SecretVec;
pub use status::Status;
