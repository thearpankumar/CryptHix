//! The epoch key that seals one kind of meta blob (FS-38, FS-57).

use std::fmt;

use crypthix_crypto::kdf::{self, KdfContext};
use crypthix_crypto::key::{KdfKey, SealKey};
use crypthix_crypto::label::SealKeyLabel;
use crypthix_crypto::secure_mem::MemError;

use crate::blob::{MetaContext, MetaKind};

/// `K_kind_e` together with the [`MetaContext`] it was derived for: the key that seals one kind
/// of meta blob in one epoch of one vault (FS-38, FS-57).
///
/// [`seal_meta_blob`](crate::blob::seal_meta_blob) and
/// [`open_meta_blob`](crate::blob::open_meta_blob) take the AAD's vault, kind and epoch from
/// here, so a key is never used with another context's AAD: a location key with a GC-candidate
/// kind byte, or one epoch's key with another epoch, would seal blobs that never open.
pub struct MetaKey {
    key: SealKey,
    context: MetaContext,
}

impl MetaKey {
    /// `K_kind_e = KDF(KEK_e, -, label, vault_id ‖ u32be(e))` for the context's kind and epoch,
    /// where `kek` is that epoch's KEK (FS-38): `kdf/index-key`, `kdf/key-table-key`,
    /// `kdf/location-key` (for location and GC-candidate nodes) or `kdf/pack-table-key`.
    ///
    /// # Errors
    ///
    /// [`MemError`] if protected memory cannot be allocated for the key.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after `kek` was made.
    pub fn derive(kek: &KdfKey, context: MetaContext) -> Result<Self, MemError> {
        let label = match context.kind() {
            MetaKind::Index => SealKeyLabel::IndexKey,
            MetaKind::KeyTable => SealKeyLabel::KeyTableKey,
            MetaKind::Location | MetaKind::GcCandidate => SealKeyLabel::LocationKey,
            MetaKind::PackTable => SealKeyLabel::PackTableKey,
        };
        let kdf_context = KdfContext::new()
            .field(context.vault_id().as_bytes())
            .u32be(context.epoch().get());
        let key = kdf::kdf(kek, None, label, &kdf_context)?;
        Ok(Self { key, context })
    }

    /// The seal key, `K_kind_e`.
    #[must_use]
    pub const fn seal_key(&self) -> &SealKey {
        &self.key
    }

    /// The vault, kind and epoch the key was derived for.
    #[must_use]
    pub const fn context(&self) -> &MetaContext {
        &self.context
    }
}

/// Prints the context, never the key.
impl fmt::Debug for MetaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetaKey")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crypthix_types::id::{Epoch, VaultId};

    use super::*;

    pub(crate) fn meta_context(kind: MetaKind, epoch: u32) -> MetaContext {
        MetaContext::new(
            VaultId::try_from_bytes([1; 16]).expect("non-zero"),
            kind,
            Epoch::try_new(epoch).expect("non-zero"),
        )
    }

    #[test]
    fn each_kind_uses_its_fs_38_label_and_context() {
        let kek = KdfKey::from_bytes([5; 32]).expect("non-zero");
        let mut context = vec![1u8; 16];
        context.extend_from_slice(&2u32.to_be_bytes());
        let context = KdfContext::from_bytes(context);
        let expected = |label: SealKeyLabel| {
            let key: SealKey = kdf::kdf(&kek, None, label, &context).expect("derives");
            key.to_bytes()
        };
        let cases = [
            (MetaKind::Index, SealKeyLabel::IndexKey),
            (MetaKind::KeyTable, SealKeyLabel::KeyTableKey),
            (MetaKind::Location, SealKeyLabel::LocationKey),
            (MetaKind::PackTable, SealKeyLabel::PackTableKey),
            (MetaKind::GcCandidate, SealKeyLabel::LocationKey),
        ];
        for (kind, label) in cases {
            let key = MetaKey::derive(&kek, meta_context(kind, 2)).expect("derives");
            assert_eq!(key.seal_key().to_bytes(), expected(label), "{kind:?}");
            assert_eq!(key.context(), &meta_context(kind, 2));
        }
        let other_epoch = MetaKey::derive(&kek, meta_context(MetaKind::Index, 3)).expect("derives");
        assert_ne!(
            other_epoch.seal_key().to_bytes(),
            expected(SealKeyLabel::IndexKey)
        );
        let printed = format!("{other_epoch:?}");
        assert!(printed.starts_with("MetaKey { context: "), "{printed}");
    }
}
