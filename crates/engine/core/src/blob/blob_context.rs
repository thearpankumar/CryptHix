//! What a data blob is bound to.

use crypthix_types::id::{DekId, ObjectId, VaultId};

/// The vault, object and DEK a data blob belongs to: the KDF context of its keys (FS-38) and
/// the fixed part of its AAD (FS-55).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlobContext {
    vault: VaultId,
    object: ObjectId,
    dek: DekId,
}

impl BlobContext {
    /// The context of one object's chunks under one DEK.
    #[must_use]
    pub const fn new(vault_id: VaultId, object_id: ObjectId, dek_id: DekId) -> Self {
        Self {
            vault: vault_id,
            object: object_id,
            dek: dek_id,
        }
    }

    /// The vault.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault
    }

    /// The object.
    #[must_use]
    pub const fn object_id(&self) -> &ObjectId {
        &self.object
    }

    /// The object's DEK.
    #[must_use]
    pub const fn dek_id(&self) -> &DekId {
        &self.dek
    }
}
