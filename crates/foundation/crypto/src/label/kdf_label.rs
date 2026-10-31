//! KDF labels: the `info` prefix of every HKDF-Expand (FS-12, FS-38).

use crate::label::labels::labels;

labels! {
    /// A label of the `kdf/` class, naming one derived key (FS-38). [`kdf`](crate::kdf::kdf)
    /// takes the typed form, such as [`SealKeyLabel`](crate::label::SealKeyLabel).
    KdfLabel, "kdf",
    /// `RK` from the root secret.
    Root => "root",
    /// The root commitment in the config, checked after recovery (FS-43).
    RootCommit => "root-commit",
    /// The wrapping key of keyring generation `g`.
    KeyringWrap => "keyring-wrap",
    /// The wrapping key of the vault signing key.
    VaultSignWrap => "vault-sign-wrap",
    /// The wrapping key of a device key (protector kind 1).
    DeviceKeyWrap => "device-key-wrap",
    /// The MAC key of the device state file.
    DeviceState => "device-state",
    /// The key of the config's sealed part.
    ConfigSeal => "config-seal",
    /// The canary seed (A6).
    CanarySeed => "canary-seed",
    /// The key of the chunker's gear table (FS-52).
    Gear => "gear",
    /// The wrapping key of the genome log key (P3).
    LogKeyWrap => "log-key-wrap",
    /// The MAC key of queue jobs (FS-86).
    QueueMac => "queue-mac",
    /// The DEK wrapping key of an epoch.
    DekWrap => "dek-wrap",
    /// The pack-key wrapping key of an epoch.
    PackKeyWrap => "pack-key-wrap",
    /// The key of path-index nodes.
    IndexKey => "index-key",
    /// The key of key-table nodes.
    KeyTableKey => "key-table-key",
    /// The key of location and GC-candidate nodes.
    LocationKey => "location-key",
    /// The key of pack-table nodes.
    PackTableKey => "pack-table-key",
    /// The key of the root's sealed part.
    RootSeal => "root-seal",
    /// The key of an object's manifest.
    ManifestKey => "manifest-key",
    /// The key of an object's data blobs.
    ChunkKey => "chunk-key",
    /// The MAC key of an object's blob IDs (FS-55).
    BlobIdKey => "blob-id-key",
    /// The MAC key of an object's whole plaintext.
    PlaintextMacKey => "plaintext-mac-key",
    /// The key of a pack header.
    PackHeaderKey => "pack-header-key",
    /// The key of a shard header.
    ShardHeaderKey => "shard-header-key",
    /// The MAC key of synthetic shard-header nonces (FS-29).
    ShardNonce => "shard-nonce",
    /// CX-AEAD encryption subkey (FS-27); used only inside CX-AEAD.
    CxKey => "cx-key",
    /// CX-AEAD commitment (FS-27); used only inside CX-AEAD.
    CxCommit => "cx-commit",
    /// CX-AEAD hedged-nonce key (FS-29); used only inside CX-AEAD.
    CxNonce => "cx-nonce",
}
