//! The key type of keyed BLAKE3.

use crate::key::secret_key::secret_key;

secret_key! {
    /// A 32-byte key for [`mac`](crate::mac::mac), derived for one purpose (FS-26, FS-38): the
    /// device state, queue jobs, blob IDs or whole-plaintext MACs.
    MacKey
}
