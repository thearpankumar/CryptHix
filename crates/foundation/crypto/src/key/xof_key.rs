//! The key type of the keyed BLAKE3 XOF.

use crate::key::secret_key::secret_key;

secret_key! {
    /// A 32-byte key for [`mac::xof`](crate::mac::xof), used only for the chunker's gear table
    /// (FS-52).
    XofKey
}
