//! The AAD of a meta blob (FS-57).

use crypthix_crypto::aad::Aad;
use crypthix_crypto::label::AadLabel;
use crypthix_types::id::BlobId;

use crate::blob::MetaContext;

/// `u8 len ‖ "crypthix/v0/aad/blob-meta" ‖ fmt ‖ suite ‖ vault_id ‖ u8 kind ‖ u32be epoch ‖
/// blob_id` (FS-57). Public only with the `vectors` feature, for the test-vector runners;
/// [`seal_meta_blob`](crate::blob::seal_meta_blob) and
/// [`open_meta_blob`](crate::blob::open_meta_blob) build it from the key's own context.
#[cfg_attr(
    not(feature = "vectors"),
    expect(unreachable_pub, reason = "public only with `vectors`, for TV-07")
)]
pub fn meta_blob_aad(context: &MetaContext, blob_id: &BlobId) -> Aad {
    Aad::new(AadLabel::BlobMeta)
        .field(context.vault_id().as_bytes())
        .u8(context.kind().code())
        .u32be(context.epoch().get())
        .field(blob_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::MetaKind;
    use crate::blob::meta_key::tests::meta_context;

    #[test]
    fn layout_is_fs_57() {
        let blob_id = BlobId::try_from_bytes([4; 32]).expect("non-zero");
        let aad = meta_blob_aad(&meta_context(MetaKind::GcCandidate, 258), &blob_id);
        let mut expected = vec![25u8];
        expected.extend_from_slice(b"crypthix/v0/aad/blob-meta");
        expected.extend_from_slice(&[0, 0, 0, 1]);
        expected.extend_from_slice(&[1; 16]);
        expected.push(0x08);
        expected.extend_from_slice(&[0, 0, 1, 2]);
        expected.extend_from_slice(&[4; 32]);
        assert_eq!(aad.as_bytes(), expected.as_slice());
    }
}
