//! The key type of CX-AEAD.

use crate::key::secret_key::secret_key;

secret_key! {
    /// A 32-byte key for [`cx_aead`](crate::cx_aead): a wrapping key or the key of a sealed
    /// field (FS-27, FS-38).
    SealKey
}
