//! The key type of synthetic shard-header nonces.

use crate::key::secret_key::secret_key;

secret_key! {
    /// `K_shn`, the key of [`NonceKind::Synthetic`](crate::cx_aead::NonceKind::Synthetic)
    /// nonces for shard headers (FS-29). It has its own type so no other MAC key can stand in.
    ShardNonceKey
}
