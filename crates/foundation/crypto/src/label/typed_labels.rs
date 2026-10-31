//! The typed label enums, one per output type of FS-38.

use crate::hash::Hash32;
use crate::key::{KdfKey, MacKey, SealKey, ShardNonceKey, XofKey};
use crate::label::derive_label::derive_labels;

derive_labels! {
    /// The labels that derive a [`SealKey`].
    SealKeyLabel => SealKey {
        KeyringWrap, VaultSignWrap, DeviceKeyWrap, ConfigSeal, LogKeyWrap, DekWrap, PackKeyWrap,
        IndexKey, KeyTableKey, LocationKey, PackTableKey, RootSeal, ManifestKey, ChunkKey,
        PackHeaderKey, ShardHeaderKey,
    }
}

derive_labels! {
    /// The labels that derive a [`MacKey`].
    MacKeyLabel => MacKey { DeviceState, QueueMac, BlobIdKey, PlaintextMacKey, }
}

derive_labels! {
    /// The label that derives the [`ShardNonceKey`].
    ShardNonceKeyLabel => ShardNonceKey { ShardNonce, }
}

derive_labels! {
    /// The labels that derive a [`KdfKey`]: `RK` and the canary seed.
    KdfKeyLabel => KdfKey { Root, CanarySeed, }
}

derive_labels! {
    /// The label that derives the gear-table [`XofKey`].
    XofKeyLabel => XofKey { Gear, }
}

derive_labels! {
    /// The label that derives `root_commit`, a public value rather than a key (FS-43).
    CommitLabel => Hash32 { RootCommit, }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::KdfLabel;

    #[test]
    fn every_label_but_cx_has_exactly_one_output_type() {
        let typed: Vec<KdfLabel> = SealKeyLabel::ALL
            .iter()
            .map(|label| KdfLabel::from(*label))
            .chain(MacKeyLabel::ALL.iter().map(|label| KdfLabel::from(*label)))
            .chain(
                ShardNonceKeyLabel::ALL
                    .iter()
                    .map(|label| KdfLabel::from(*label)),
            )
            .chain(KdfKeyLabel::ALL.iter().map(|label| KdfLabel::from(*label)))
            .chain(XofKeyLabel::ALL.iter().map(|label| KdfLabel::from(*label)))
            .chain(CommitLabel::ALL.iter().map(|label| KdfLabel::from(*label)))
            .collect();
        for label in KdfLabel::ALL {
            let count = typed.iter().filter(|typed| *typed == label).count();
            let internal = matches!(
                label,
                KdfLabel::CxKey | KdfLabel::CxCommit | KdfLabel::CxNonce
            );
            assert_eq!(
                count,
                usize::from(!internal),
                "{label:?} has {count} output types"
            );
        }
    }
}
