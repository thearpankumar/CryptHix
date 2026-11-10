//! The kinds of meta blob (format spec 10.4).

/// A meta blob's kind: the tree node it holds, and its kind byte in the AAD (FS-57).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MetaKind {
    /// 0x03: a path-index node, sealed under `K_idx_e`.
    Index,
    /// 0x04: a key-table node, sealed under `K_kt_e`.
    KeyTable,
    /// 0x05: a location node, sealed under `K_loc_e`.
    Location,
    /// 0x06: a pack-table node, sealed under `K_pt_e`.
    PackTable,
    /// 0x08: a GC-candidate node, sealed under `K_loc_e`; the kind byte keeps it apart from
    /// location nodes.
    GcCandidate,
}

impl MetaKind {
    /// The kind byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            MetaKind::Index => 0x03,
            MetaKind::KeyTable => 0x04,
            MetaKind::Location => 0x05,
            MetaKind::PackTable => 0x06,
            MetaKind::GcCandidate => 0x08,
        }
    }

    /// The kind a byte names; `None` for data (0x01), manifest (0x02), the reserved snapshot
    /// node (0x07) and anything unknown. For the unit tests and, with the `vectors` feature, the
    /// test-vector runners.
    #[cfg(any(test, feature = "vectors"))]
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x03 => Some(MetaKind::Index),
            0x04 => Some(MetaKind::KeyTable),
            0x05 => Some(MetaKind::Location),
            0x06 => Some(MetaKind::PackTable),
            0x08 => Some(MetaKind::GcCandidate),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind, in code order.
    const ALL: [MetaKind; 5] = [
        MetaKind::Index,
        MetaKind::KeyTable,
        MetaKind::Location,
        MetaKind::PackTable,
        MetaKind::GcCandidate,
    ];

    #[test]
    fn codes_round_trip_and_others_are_not_meta() {
        for kind in ALL {
            assert_eq!(MetaKind::from_code(kind.code()), Some(kind));
        }
        let known: Vec<u8> = ALL.iter().map(|kind| kind.code()).collect();
        assert_eq!(known, [3, 4, 5, 6, 8]);
        for code in [0, 1, 2, 7, 9, 0xFF] {
            assert_eq!(MetaKind::from_code(code), None, "{code}");
        }
    }
}
