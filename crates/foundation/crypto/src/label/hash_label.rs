//! Hash labels: the domain of every `H` (section 7.1).

use crate::label::labels::labels;

labels! {
    /// A label of the `hash/` class, naming one use of `H`.
    HashLabel, "hash",
    /// `vault_id` from the master public key and vault nonce (FS-02).
    VaultId => "vault-id",
    /// `key_id` of a public key.
    KeyId => "key-id",
    /// `shard_id` of a whole shard file (FS-63).
    ShardId => "shard-id",
    /// The hash of a sealed blob.
    Blob => "blob",
    /// The hash of a whole pack.
    Pack => "pack",
    /// The hash of a whole file.
    File => "file",
    /// A variable-length AAD field (FS-12).
    AadPart => "aad-part",
    /// The CX-AEAD AAD digest `a` (FS-27).
    CxAad => "cx-aad",
    /// Manifest Merkle leaves, nodes and root (FS-66).
    MerkleManifest => "merkle-manifest",
    /// The chain of vault roots.
    RootChain => "root-chain",
    /// The chain of genome log entries.
    LogChain => "log-chain",
    /// The recovery sheet fingerprint (FS-45).
    RecoveryCheck => "recovery-check",
}
