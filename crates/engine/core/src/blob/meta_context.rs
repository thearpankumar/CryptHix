//! What a meta blob is bound to.

use crypthix_types::id::{Epoch, VaultId};

use crate::blob::MetaKind;

/// The vault, kind and epoch of a meta blob: the fixed part of its AAD (FS-57).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MetaContext {
    vault_id: VaultId,
    kind: MetaKind,
    epoch: Epoch,
}

impl MetaContext {
    /// The context of one kind of node under one epoch.
    #[must_use]
    pub const fn new(vault_id: VaultId, kind: MetaKind, epoch: Epoch) -> Self {
        Self {
            vault_id,
            kind,
            epoch,
        }
    }

    /// The vault.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The kind of node.
    #[must_use]
    pub const fn kind(&self) -> MetaKind {
        self.kind
    }

    /// The epoch whose key seals it.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
}
