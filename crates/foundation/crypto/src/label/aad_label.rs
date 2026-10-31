//! AAD labels: the first field of every CX-AEAD associated data (FS-12).

use crate::label::labels::labels;

labels! {
    /// A label of the `aad/` class, naming one kind of sealed field.
    AadLabel, "aad",
    /// A share slot's wrap (section 9.1).
    ShareSlot => "share-slot",
    /// A keyring generation's wrap.
    Keyring => "keyring",
    /// An epoch key file's wrap.
    Epoch => "epoch",
    /// The wrapped vault signing key.
    VaultSignKey => "vault-sign-key",
    /// A wrapped device key.
    DeviceKey => "device-key",
    /// A DEK wrap (section 9.7).
    DekWrap => "dek-wrap",
    /// A pack-key wrap (section 9.7).
    PackKeyWrap => "pack-key-wrap",
    /// A data blob (FS-55).
    BlobData => "blob-data",
    /// A meta blob (FS-57).
    BlobMeta => "blob-meta",
    /// An object manifest.
    Manifest => "manifest",
    /// A pack header (FS-60).
    PackHeader => "pack-header",
    /// A shard header.
    ShardHeader => "shard-header",
    /// The config's sealed part.
    ConfigSeal => "config-seal",
    /// The root's sealed part.
    RootSeal => "root-seal",
    /// A genome log body (P3).
    LogDetails => "log-details",
    /// The wrapped genome log key (P3).
    LogKey => "log-key",
}

impl AadLabel {
    /// Whether the label seals a key (a key wrap), which only
    /// [`cx_aead::seal_key`](crate::cx_aead::seal_key) and
    /// [`cx_aead::open_key`](crate::cx_aead::open_key) may use, so a wrapped key's bytes never
    /// leave the crate (backlog rule 9).
    #[must_use]
    pub const fn is_key_wrap(self) -> bool {
        matches!(
            self,
            AadLabel::Keyring
                | AadLabel::Epoch
                | AadLabel::VaultSignKey
                | AadLabel::DeviceKey
                | AadLabel::DekWrap
                | AadLabel::PackKeyWrap
                | AadLabel::LogKey
        )
    }
}
