//! Read modes.

/// Whether a read may be served from a cache. This set is fixed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ReadMode {
    /// Caches are allowed.
    Cached,
    /// Read from the medium, bypassing every cache: the read-back check before a commit (FS-88,
    /// M-45).
    Uncached,
}
