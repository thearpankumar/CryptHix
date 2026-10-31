//! The key type of HKDF input keying material.

use crate::key::secret_key::secret_key;

secret_key! {
    /// A 32-byte secret that only feeds [`kdf`](crate::kdf::kdf): the root secret, `RK`, an
    /// epoch KEK, a DEK, a pack key or the chunker seed (FS-31 to FS-35, FS-38).
    KdfKey
}
