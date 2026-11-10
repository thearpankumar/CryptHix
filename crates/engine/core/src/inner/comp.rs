//! The compression code of an inner plaintext (FS-54).

/// How a chunk's payload is stored (FS-53, FS-54).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Comp {
    /// Code 0: the chunk's own bytes, uncompressed.
    Raw,
    /// Code 1: one zstd frame of the chunk.
    Zstd,
}

impl Comp {
    /// The byte stored in the inner plaintext.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Comp::Raw => 0,
            Comp::Zstd => 1,
        }
    }

    /// The compression a stored byte names; `None` for any byte but 0 and 1, which a reader
    /// rejects as `Padding` (FS-54).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Comp::Raw),
            1 => Some(Comp::Zstd),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_and_nothing_else_is_known() {
        for comp in [Comp::Raw, Comp::Zstd] {
            assert_eq!(Comp::from_code(comp.code()), Some(comp));
        }
        assert_eq!(Comp::Raw.code(), 0);
        assert_eq!(Comp::Zstd.code(), 1);
        for code in 2..=u8::MAX {
            assert_eq!(Comp::from_code(code), None, "{code}");
        }
    }
}
