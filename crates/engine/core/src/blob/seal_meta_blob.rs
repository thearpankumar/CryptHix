//! Sealing a meta blob (FS-57).

use crypthix_crypto::cx_aead::{self, NonceKind};
use crypthix_crypto::random;
use crypthix_types::id::BlobId;

use crate::blob::{self, MetaKey, SealedMeta};
use crate::error::WriteError;

/// Seals the CBOR of a tree node as a meta blob under `key`, with the AAD of the context it was
/// derived for, a random blob ID and a hedged nonce (FS-57).
///
/// # Errors
///
/// - [`WriteError::Random`] if the kernel gives no random blob ID.
/// - [`WriteError::Seal`] if the seal fails.
///
/// # Panics
///
/// On Linux, in a child forked without `exec` after `key` was made.
pub fn seal_meta_blob(key: &MetaKey, cbor: &[u8]) -> Result<SealedMeta, WriteError> {
    let blob_id = BlobId::try_from_bytes(random::bytes::<32>()?)?;
    let aad = blob::meta_blob_aad(key.context(), &blob_id);
    let sealed = cx_aead::seal(key.seal_key(), &aad, cbor, NonceKind::Hedged)?;
    Ok(SealedMeta::new(blob_id, sealed))
}
