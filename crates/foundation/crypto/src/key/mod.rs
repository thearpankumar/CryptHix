//! Zeroizing key types, one per primitive (FS-25, backlog rule 9).
//!
//! Each type holds 32 secret bytes, wipes them on drop, has no `Clone`, and never shows its bytes
//! outside this crate: keys are created at random, derived with [`kdf`](crate::kdf), or unwrapped
//! with [`cx_aead::open_key`](crate::cx_aead::open_key). A key cannot be used with the wrong
//! primitive, because each primitive takes its own type.

pub(crate) mod check_nonzero;
mod kdf_key;
mod key_material;
mod mac_key;
mod passphrase;
mod seal_key;
pub(crate) mod sealed;
mod secret_key;
mod shard_nonce_key;
mod xof_key;

pub use kdf_key::KdfKey;
pub use key_material::KeyMaterial;
pub use mac_key::MacKey;
pub use passphrase::Passphrase;
pub use seal_key::SealKey;
pub use shard_nonce_key::ShardNonceKey;
pub use xof_key::XofKey;
