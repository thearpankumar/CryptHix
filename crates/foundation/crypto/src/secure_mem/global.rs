//! The process-wide key pool.
#![expect(
    unsafe_code,
    reason = "a lock-free pointer to the pool, so a forked child never waits on a lock"
)]

use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::secure_mem::key_pool::KeyPool;
use crate::secure_mem::{Config, KeySlot, MemError, Status, buffer_level, fork_generation};

/// The one pool every key of the process lives in. A single pool means one place enforces the
/// minimum level and no caller can hand a key a weaker one.
///
/// It is set up once, by [`init`], or with [`Config::default`] by the first key or the first
/// plaintext buffer, whichever comes first; [`status`] never sets it up. Buffers set it up too
/// because on Linux they lock what the pool's share of `RLIMIT_MEMLOCK` leaves (`lock_budget`),
/// and that share is read from the pool: so it is known before any buffer locks, and an `init`
/// that comes too late to set it is refused instead of silently getting less.
///
/// This is one of the crate's process-wide statics, all in `secure_mem` and all atomics (backlog
/// rule 6): this pool; on Linux, the lock budget's two counters of locked bytes, `KEYS` and
/// `BUFFERS`, which mirror a limit that is itself per process, and the fork generation
/// (`fork_generation`: its marker page, the latest generation and a fork count); and `WEAKEST`
/// and `REASON`, the weakest level a plaintext buffer got and why the latest buffer fell below
/// locked, for [`status`].
///
/// A child forked without `exec` inherits this pointer but not the arenas behind it
/// (`MADV_DONTFORK`); the pool's fork generation tells it so, and its first `init`, key or
/// buffer sets up a pool of its own and never touches the parent's. Its lock budget, buffer
/// level and buffer reason start empty (`fork_generation`). The pointer is an atomic rather
/// than a `OnceLock` or `Mutex` because another thread of the parent may have held such a lock
/// at the fork, and the child would then wait on it forever.
///
/// Null, or a pool from [`Box::into_raw`] in [`install`] that is never freed.
static POOL: AtomicPtr<KeyPool> = AtomicPtr::new(ptr::null_mut());

/// Sets up protected memory for keys, once, before the first key or plaintext buffer exists,
/// and maps the first arena so a level below `config`'s minimum fails here rather than at the
/// first key.
///
/// Without it, the first key or plaintext buffer sets up the pool with [`Config::default`].
/// So an app calls `init` before anything that makes either: a key of any type, a
/// [`SecretBuf`](crate::secure_mem::SecretBuf) (even an empty one), a
/// [`Passphrase`](crate::key::Passphrase), `cx_aead::open`, Argon2id, signing or verifying.
/// Calling it later fails loudly with [`MemError::AlreadyInitialised`] rather than leave the
/// app with the default's minimum and share of `RLIMIT_MEMLOCK` (see
/// [`Config::with_max_pages`]). [`status`] sets up nothing, so it may come first. A child
/// forked without `exec` starts with no pool, so it may call `init` again.
///
/// The same rule as a global thread pool that its first use sets up with defaults and that
/// refuses a configuration once it exists (rayon's
/// [`ThreadPoolBuilder::build_global`](https://docs.rs/rayon/latest/rayon/struct.ThreadPoolBuilder.html#method.build_global)),
/// and unlike OpenSSL's secure heap, whose allocations before
/// [`CRYPTO_secure_malloc_init`](https://docs.openssl.org/master/man3/CRYPTO_secure_malloc/)
/// quietly fall back to plain `OPENSSL_malloc`.
///
/// A first arena in `memfd_secret` memory stays mapped until the process exits, and the kernel
/// does not hibernate while it exists.
///
/// The pool is set up with `config` even when mapping its first arena fails, so an app that
/// carries on anyway still never gets a key below its minimum: each later key tries again and
/// fails the same way, and [`status`] keeps the error in [`Status::last_failure`].
///
/// # Errors
///
/// - [`MemError::AlreadyInitialised`] if this process already has a pool: from an earlier
///   `init` (failed or not), the first key, or the first plaintext buffer, including the
///   buffers made inside the calls listed above. Nothing is mapped then, and this error comes
///   before any other.
/// - [`MemError::BelowMinimum`] if the system cannot give the minimum level.
/// - [`MemError::MapFailed`] if the kernel refuses every mapping.
pub fn init(config: Config) -> Result<Status, MemError> {
    let pool = install(KeyPool::new(config)).map_err(|_| MemError::AlreadyInitialised)?;
    pool.reserve()?;
    Ok(status())
}

/// The protection keys and plaintext buffers have got so far.
///
/// A report that never sets up the pool, so [`init`] may still follow it; on Linux its first
/// call only sets up the fork generation's marker page, as anything here does. Before the pool
/// exists, [`Status::initialised`] is `false` and the report is that of the pool the first key
/// or buffer would set up.
///
/// ```
/// use crypthix_crypto::key::SealKey;
/// use crypthix_crypto::secure_mem::{self, Level};
///
/// let key = SealKey::random()?;
/// let status = secure_mem::status();
/// assert!(status.initialised, "the first key set up the pool");
/// assert!(status.key_level >= Some(Level::platform_floor()));
/// assert!(status.key_slots_used >= 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub fn status() -> Status {
    // The fork generation first, pool or not: in a forked child, taking it clears the parent's
    // buffer level and reason before they are read here.
    fork_generation::current();
    let mut status = own(POOL.load(Ordering::Acquire)).map_or_else(no_pool, KeyPool::status);
    status.buffer_level = buffer_level::weakest();
    status.buffer_reason = buffer_level::reason();
    status
}

/// The report before this process has a pool: no keys, and the minimum of [`Config::default`],
/// the one the first key or buffer would set up.
fn no_pool() -> Status {
    Status {
        initialised: false,
        key_level: None,
        buffer_level: None,
        buffer_reason: None,
        minimum: Config::default().minimum(),
        key_slots_used: 0,
        key_slots_total: 0,
        reason: None,
        last_failure: None,
    }
}

/// A free key slot from the process-wide pool.
pub(crate) fn take_key_slot() -> Result<KeySlot, MemError> {
    pool().slot()
}

/// Sets up this process's pool with [`Config::default`] if there is none yet, as the first
/// plaintext buffer does before it maps anything.
pub(crate) fn set_up_pool() {
    pool();
}

/// The bytes of `RLIMIT_MEMLOCK` kept for key arenas: what this process's pool can charge at
/// most. Its first charge sets up the pool if a buffer or key has not already.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn key_lock_reserve() -> usize {
    pool().lock_reserve()
}

/// This process's pool, set up with [`Config::default`] if there is none yet.
fn pool() -> &'static KeyPool {
    loop {
        if let Some(pool) = own(POOL.load(Ordering::Acquire)) {
            return pool;
        }
        // On a lost race another thread installed a pool, which the next pass returns.
        if let Ok(pool) = install(KeyPool::new(Config::default())) {
            return pool;
        }
    }
}

/// Makes `pool` this process's pool, or hands it back if the process already has one. From
/// then on its share of `RLIMIT_MEMLOCK` is kept for keys, since every charge reads the share
/// from the pool this returns ([`key_lock_reserve`]).
fn install(pool: KeyPool) -> Result<&'static KeyPool, KeyPool> {
    let seen = POOL.load(Ordering::Acquire);
    if own(seen).is_some() {
        return Err(pool);
    }
    let new = Box::into_raw(Box::new(pool));
    match POOL.compare_exchange(seen, new, Ordering::AcqRel, Ordering::Acquire) {
        // SAFETY: `new` is a live allocation from `Box::into_raw` just above, now stored in
        // `POOL`, which never frees it, so it lives for the rest of the process.
        Ok(_) => Ok(unsafe { &*new }),
        // SAFETY: another thread of this process stored its pool first, so `new` was never
        // shared; this reclaims the only owner of the allocation made above.
        Err(_) => Err(*unsafe { Box::from_raw(new) }),
    }
}

/// The pool `pool` points at, if this process made it.
fn own(pool: *mut KeyPool) -> Option<&'static KeyPool> {
    // SAFETY: a value of `POOL`: null, or a pool that is never freed. In a forked child it
    // points into the child's private copy of the parent's heap, which is valid memory; only
    // its generation is read there, never its lock or arenas.
    let pool = unsafe { pool.as_ref() }?;
    pool.in_this_process().then_some(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_mem::Level;

    #[test]
    fn init_after_the_pool_exists_is_refused_before_anything_else() {
        let _slot = take_key_slot().expect("the default pool works");
        let before = status();
        assert_eq!(
            init(Config::default()).err(),
            Some(MemError::AlreadyInitialised)
        );
        // This minimum is out of reach, so an `init` that mapped before checking would say so.
        assert_eq!(
            init(
                Config::default()
                    .with_strongest(Level::Heap)
                    .with_minimum(Level::Locked)
            )
            .err(),
            Some(MemError::AlreadyInitialised)
        );
        let after = status();
        assert_eq!(after.minimum, before.minimum, "the first pool stays");
        assert_eq!(
            after.last_failure, before.last_failure,
            "the refused config was never tried"
        );
    }
}
