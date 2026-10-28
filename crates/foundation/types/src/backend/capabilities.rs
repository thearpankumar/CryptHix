//! Backend capabilities.

/// A set of features a backend declares.
///
/// These are declarations by the implementation. A store's filesystem or provider can still
/// fall short of them (NFS, FUSE or tmpfs locally), so `init` also probes the store before it
/// trusts [`Capabilities::ATOMIC_CREATE`] (FS-87).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct Capabilities(u8);

impl Capabilities {
    /// Nothing supported.
    pub const NONE: Self = Self(0);
    /// [`PutMode::IfAbsent`](crate::backend::PutMode::IfAbsent) is atomic: a no-replace link
    /// locally, `If-None-Match: *` on S3 (FS-87). Required to hold roots.
    pub const ATOMIC_CREATE: Self = Self(1);
    /// [`ReadMode::Uncached`](crate::backend::ReadMode::Uncached) really bypasses caches
    /// (FS-88).
    pub const UNCACHED_READ: Self = Self(1 << 1);
    /// Range reads cost less than whole-file reads.
    pub const RANGED_GET: Self = Self(1 << 2);
    /// Files can be locked against deletion (S3 Object Lock and equivalents).
    pub const OBJECT_LOCK: Self = Self(1 << 3);

    /// Both sets together.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every capability of `other` is in this set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets() {
        let local = Capabilities::ATOMIC_CREATE.union(Capabilities::UNCACHED_READ);
        assert!(
            local.contains(Capabilities::ATOMIC_CREATE),
            "union keeps both"
        );
        assert!(
            !local.contains(Capabilities::OBJECT_LOCK),
            "union adds nothing else"
        );
        assert!(
            local.contains(Capabilities::NONE),
            "every set contains the empty set"
        );
        assert!(
            !Capabilities::NONE.contains(Capabilities::RANGED_GET),
            "empty set is empty"
        );
    }
}
