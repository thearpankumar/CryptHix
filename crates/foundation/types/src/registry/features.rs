//! Feature bits (FS-21).

use crate::format_error::FormatError;
use crate::registry::grease;

/// The three feature bit sets of the config and of every vault root (ext4 style).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct Features {
    compat: u64,
    ro_compat: u64,
    incompat: u64,
}

impl Features {
    /// No bits set.
    pub const EMPTY: Self = Self {
        compat: 0,
        ro_compat: 0,
        incompat: 0,
    };

    /// `ro_compat` bit 0: the genome log is present. Reserved for Phase 3.
    pub const RO_COMPAT_LOG: u32 = 0;
    /// `ro_compat` bit 1: snapshots are present. Reserved for Phase 3.
    pub const RO_COMPAT_SNAPSHOTS: u32 = 1;
    /// `ro_compat` bit 2: erasure coding with m > 0. Reserved for Phase 4.
    pub const RO_COMPAT_ERASURE: u32 = 2;
    /// `incompat` bit 3: several devices may write. Reserved for Phase 4.
    pub const INCOMPAT_MULTI_WRITER: u32 = 3;

    /// Builds a feature set from its three raw bit sets.
    #[must_use]
    pub const fn new(compat: u64, ro_compat: u64, incompat: u64) -> Self {
        Self {
            compat,
            ro_compat,
            incompat,
        }
    }

    /// Bits a reader that does not know them may ignore.
    #[must_use]
    pub const fn compat(self) -> u64 {
        self.compat
    }

    /// Bits a reader that does not know them may read but not write.
    #[must_use]
    pub const fn ro_compat(self) -> u64 {
        self.ro_compat
    }

    /// Bits a reader that does not know them must reject.
    #[must_use]
    pub const fn incompat(self) -> u64 {
        self.incompat
    }

    /// The union of two feature sets, as kept in `features_seen`.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            compat: self.compat | other.compat,
            ro_compat: self.ro_compat | other.ro_compat,
            incompat: self.incompat | other.incompat,
        }
    }

    /// Whether every bit of `other` is also set here.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.compat & other.compat == other.compat
            && self.ro_compat & other.ro_compat == other.ro_compat
            && self.incompat & other.incompat == other.incompat
    }

    /// Checks that a reader that knows `known` may read a vault with these features.
    ///
    /// # Errors
    ///
    /// [`FormatError::Feature`] for an unknown `incompat` bit. GREASE bits are ignored.
    pub const fn check_read(self, known: Self) -> Result<(), FormatError> {
        if unknown(self.incompat, known.incompat) != 0 {
            return Err(FormatError::Feature);
        }
        Ok(())
    }

    /// Checks that a writer that knows `known` may write, commit or garbage-collect.
    ///
    /// # Errors
    ///
    /// [`FormatError::Feature`] for an unknown `incompat` or `ro_compat` bit. GREASE bits are
    /// ignored.
    pub const fn check_write(self, known: Self) -> Result<(), FormatError> {
        if unknown(self.ro_compat, known.ro_compat) != 0 {
            return Err(FormatError::Feature);
        }
        self.check_read(known)
    }
}

/// Bits of `set` that are neither in `known` nor GREASE.
const fn unknown(set: u64, known: u64) -> u64 {
    set & !known & !grease::GREASE_BITS
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: Features = Features::EMPTY;

    #[test]
    fn unknown_compat_bit_is_ignored() {
        let features = Features::new(1 << 7, 0, 0);
        assert_eq!(features.check_read(KNOWN), Ok(()));
        assert_eq!(features.check_write(KNOWN), Ok(()));
    }

    #[test]
    fn unknown_ro_compat_bit_allows_reads_only() {
        let features = Features::new(0, 1 << Features::RO_COMPAT_LOG, 0);
        assert_eq!(features.check_read(KNOWN), Ok(()));
        assert_eq!(features.check_write(KNOWN), Err(FormatError::Feature));
        let known = Features::new(0, 1 << Features::RO_COMPAT_LOG, 0);
        assert_eq!(features.check_write(known), Ok(()));
    }

    #[test]
    fn unknown_incompat_bit_is_rejected() {
        let features = Features::new(0, 0, 1 << Features::INCOMPAT_MULTI_WRITER);
        assert_eq!(features.check_read(KNOWN), Err(FormatError::Feature));
    }

    #[test]
    fn grease_bits_are_ignored() {
        let grease = grease::GREASE_BITS;
        let features = Features::new(grease, grease, grease);
        assert_eq!(features.check_read(KNOWN), Ok(()));
        assert_eq!(features.check_write(KNOWN), Ok(()));
    }

    #[test]
    fn union_and_contains() {
        let a = Features::new(1, 2, 0);
        let b = Features::new(0, 4, 8);
        let both = a.union(b);
        assert!(
            both.contains(a) && both.contains(b),
            "a union contains both parts"
        );
        assert!(!a.contains(both), "a part does not contain the union");
    }
}
