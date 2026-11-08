//! What protection the process got.

use crate::secure_mem::{Fallback, Level, MemError};

/// A report of the protection keys and plaintext buffers got, for `crypthix status` and the
/// daemon's hardening mode (M-13).
///
/// `key_level` describes the keys that exist; `last_failure` the latest arena that could not be
/// added, whose keys were never made. So a pool whose first arena is [`Level::Secret`] keeps
/// reporting `Secret` after a later arena fails with [`MemError::BelowMinimum`]: every key made
/// is in secret memory, and `reason` and `last_failure` say why no more could be made.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Status {
    /// Whether this process has set up its key pool: by [`init`](crate::secure_mem::init), or
    /// with [`Config::default`](crate::secure_mem::Config::default) by its first key or
    /// plaintext buffer. While it is `false`, `init` may still be called, no key exists, and
    /// `minimum` is the default's, which the first key or buffer would set up. A child forked
    /// without `exec` reports `false` until it sets up a pool of its own.
    pub initialised: bool,
    /// The weakest level of any key arena mapped so far, which every existing key has at
    /// least; `None` before the first arena.
    pub key_level: Option<Level>,
    /// The weakest level of any plaintext buffer so far, even one since dropped; `None` before
    /// the first one.
    pub buffer_level: Option<Level>,
    /// Why the latest plaintext buffer that fell below [`Level::Locked`] did, or why the latest
    /// one that could not be made at all was refused ([`MemError::MapFailed`]); `None` while
    /// every buffer was locked. Like `buffer_level` it is never raised again: a later locked
    /// buffer leaves it unchanged. A buffer refused as [`MemError::TooLarge`] tried no level
    /// and leaves it unchanged too. Off Linux and under Miri it is [`Fallback::Platform`] once
    /// a buffer exists.
    pub buffer_reason: Option<Fallback>,
    /// The minimum the pool enforces for keys; before it is set up (`initialised` is `false`),
    /// that of [`Config::default`](crate::secure_mem::Config::default).
    pub minimum: Level,
    /// Key slots in use.
    pub key_slots_used: usize,
    /// Key slots mapped, used or free.
    pub key_slots_total: usize,
    /// Why the latest key arena that fell below the strongest level did, whether it was kept
    /// or refused for being below the minimum; `None` while every arena tried got the strongest
    /// level. An arena that later gets the strongest level leaves it unchanged, since the
    /// weaker arena still exists.
    pub reason: Option<Fallback>,
    /// The error of the latest attempt to add a key arena, including one made by a failed
    /// [`init`](crate::secure_mem::init); `None` if none failed. A later arena that maps
    /// leaves it unchanged.
    pub last_failure: Option<MemError>,
}
