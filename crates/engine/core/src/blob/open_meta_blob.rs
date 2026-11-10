//! Opening a meta blob (FS-57).

use crypthix_crypto::cx_aead;
use crypthix_crypto::secure_mem::SecretBuf;
use crypthix_types::id::BlobId;

use crate::blob::{MetaKey, meta_blob_aad};
use crate::error::ReadError;

/// Opens the meta blob `blob_id` under `key`, with the AAD of the context it was derived for,
/// and returns its CBOR in protected memory. The CBOR is not checked here; its decoder applies
/// FS-08 to FS-11.
///
/// # Errors
///
/// - [`ReadError::Format`] with `Decrypt` for any change to the key, vault, kind, epoch, blob
///   ID or sealed bytes, or `Truncated` / `ZeroValue` for input too short to be a seal or with
///   a zero nonce.
/// - [`ReadError::Memory`] if protected memory cannot be allocated for the plaintext.
///
/// # Panics
///
/// On Linux, in a child forked without `exec` after `key` was made.
pub fn open_meta_blob(
    key: &MetaKey,
    blob_id: &BlobId,
    sealed: &[u8],
) -> Result<SecretBuf, ReadError> {
    let aad = meta_blob_aad(key.context(), blob_id);
    Ok(cx_aead::open(key.seal_key(), &aad, sealed)?)
}

#[cfg(test)]
mod tests {
    use crypthix_crypto::cx_aead::NonceKind;
    use crypthix_crypto::key::KdfKey;
    use crypthix_types::format_error::FormatError;
    use crypthix_types::id::{Epoch, VaultId};

    use super::*;
    use crate::blob::meta_key::tests::meta_context;
    use crate::blob::{MetaContext, MetaKind, seal_meta_blob};

    const DECRYPT: Result<(), ReadError> = Err(ReadError::Format(FormatError::Decrypt));

    fn kek() -> KdfKey {
        KdfKey::from_bytes([5; 32]).expect("non-zero")
    }

    fn key(context: MetaContext) -> MetaKey {
        MetaKey::derive(&kek(), context).expect("derives")
    }

    fn open(key: &MetaKey, blob_id: &BlobId, sealed: &[u8]) -> Result<(), ReadError> {
        open_meta_blob(key, blob_id, sealed).map(|_| ())
    }

    #[test]
    fn meta_blobs_round_trip_with_random_ids() {
        let key = key(meta_context(MetaKind::PackTable, 2));
        let first = seal_meta_blob(&key, b"\xa0").expect("seals");
        let second = seal_meta_blob(&key, b"\xa0").expect("seals");
        assert_ne!(first.blob_id(), second.blob_id(), "blob IDs are random");
        let opened = open_meta_blob(&key, first.blob_id(), first.sealed()).expect("opens");
        assert_eq!(opened.as_slice(), b"\xa0");
        let id = *second.blob_id();
        let bytes = second.into_sealed();
        let opened = open_meta_blob(&key, &id, &bytes).expect("the owned bytes open");
        assert_eq!(opened.as_slice(), b"\xa0");
    }

    #[test]
    fn every_bound_field_is_checked() {
        let context = meta_context(MetaKind::Location, 2);
        let key = key(context);
        let sealed = seal_meta_blob(&key, b"node").expect("seals");
        let id = *sealed.blob_id();
        let bytes = sealed.sealed();
        let other_id = BlobId::try_from_bytes([9; 32]).expect("non-zero");
        assert_eq!(open(&key, &other_id, bytes), DECRYPT, "blob ID");
        // A blob sealed under the right key with another context's AAD never opens, so each
        // AAD field is bound. A GC-candidate node shares the location key; only the kind byte
        // differs.
        let later = MetaContext::new(
            *context.vault_id(),
            context.kind(),
            Epoch::try_new(3).expect("non-zero"),
        );
        let vault = MetaContext::new(
            VaultId::try_from_bytes([2; 16]).expect("non-zero"),
            context.kind(),
            context.epoch(),
        );
        for (other, field) in [
            (meta_context(MetaKind::GcCandidate, 2), "kind"),
            (later, "epoch"),
            (vault, "vault"),
        ] {
            let aad = meta_blob_aad(&other, &id);
            let resealed =
                cx_aead::seal(key.seal_key(), &aad, b"node", NonceKind::Hedged).expect("seals");
            assert_eq!(open(&key, &id, &resealed), DECRYPT, "{field}");
        }
        let other_key = self::key(meta_context(MetaKind::Index, 2));
        assert_eq!(open(&other_key, &id, bytes), DECRYPT, "key");
        let mut flipped = bytes.to_vec();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(open(&key, &id, &flipped), DECRYPT, "tag");
        assert_eq!(
            open(&key, &id, &bytes[..71]),
            Err(ReadError::Format(FormatError::Truncated))
        );
    }

    #[test]
    fn an_all_zero_nonce_is_a_zero_value() {
        let key = key(meta_context(MetaKind::KeyTable, 2));
        let sealed = seal_meta_blob(&key, b"node").expect("seals");
        let mut zeroed = sealed.sealed().to_vec();
        zeroed[..cx_aead::NONCE_LEN].fill(0);
        assert_eq!(
            open(&key, sealed.blob_id(), &zeroed),
            Err(ReadError::Format(FormatError::ZeroValue)),
            "checked before the tag, which no longer matches"
        );
    }
}
