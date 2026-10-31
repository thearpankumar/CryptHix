//! The label registry of format spec section 7.1, copied from the spec rather than from
//! `crypthix-crypto`, so TV-04 checks that crate's registry.

/// `kdf/` purposes.
pub(crate) const KDF: [&str; 28] = [
    "root",
    "root-commit",
    "keyring-wrap",
    "vault-sign-wrap",
    "device-key-wrap",
    "device-state",
    "config-seal",
    "canary-seed",
    "gear",
    "log-key-wrap",
    "queue-mac",
    "dek-wrap",
    "pack-key-wrap",
    "index-key",
    "key-table-key",
    "location-key",
    "pack-table-key",
    "root-seal",
    "manifest-key",
    "chunk-key",
    "blob-id-key",
    "plaintext-mac-key",
    "pack-header-key",
    "shard-header-key",
    "shard-nonce",
    "cx-key",
    "cx-commit",
    "cx-nonce",
];

/// `aad/` purposes.
pub(crate) const AAD: [&str; 16] = [
    "share-slot",
    "keyring",
    "epoch",
    "vault-sign-key",
    "device-key",
    "dek-wrap",
    "pack-key-wrap",
    "blob-data",
    "blob-meta",
    "manifest",
    "pack-header",
    "shard-header",
    "config-seal",
    "root-seal",
    "log-details",
    "log-key",
];

/// `sig/` purposes.
pub(crate) const SIG: [&str; 9] = [
    "config",
    "device-cert",
    "device-pop",
    "device-set",
    "root",
    "manifest",
    "log-entry",
    "snapshot",
    "epoch-device-wrap",
];

/// `hash/` purposes.
pub(crate) const HASH: [&str; 12] = [
    "vault-id",
    "key-id",
    "shard-id",
    "blob",
    "pack",
    "file",
    "aad-part",
    "cx-aad",
    "merkle-manifest",
    "root-chain",
    "log-chain",
    "recovery-check",
];

/// Every full label, `crypthix/v0/<class>/<purpose>`.
pub(crate) fn all() -> Vec<&'static str> {
    [
        ("kdf", &KDF[..]),
        ("aad", &AAD[..]),
        ("sig", &SIG[..]),
        ("hash", &HASH[..]),
    ]
    .iter()
    .flat_map(|(class, purposes)| purposes.iter().map(move |purpose| full(class, purpose)))
    .collect()
}

/// `crypthix/v0/<class>/<purpose>` as a `'static` string. Each call leaks a short string, which
/// is fine for a generator that runs once and exits.
pub(crate) fn full(class: &str, purpose: &str) -> &'static str {
    Box::leak(format!("crypthix/v0/{class}/{purpose}").into_boxed_str())
}
