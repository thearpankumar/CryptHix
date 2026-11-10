//! The AAD of a data blob (FS-55).

use crypthix_crypto::aad::Aad;
use crypthix_crypto::label::AadLabel;
use crypthix_types::id::BlobId;

use crate::blob::BlobContext;

/// The blob kind byte of a data blob (format spec 10.4).
const DATA_BLOB_KIND: u8 = 0x01;

/// `u8 len ‖ "crypthix/v0/aad/blob-data" ‖ fmt ‖ suite ‖ vault_id ‖ u8 0x01 ‖ object_id ‖
/// dek_id ‖ blob_id` (FS-55). Public only with the `vectors` feature, for the test-vector
/// runners and fuzz targets; [`ObjectSealer`](crate::blob::ObjectSealer) and
/// [`ObjectOpener`](crate::blob::ObjectOpener) build it from the keys' own context.
#[cfg_attr(
    not(feature = "vectors"),
    expect(unreachable_pub, reason = "public only with `vectors`, for TV-07")
)]
pub fn data_blob_aad(context: &BlobContext, blob_id: &BlobId) -> Aad {
    Aad::new(AadLabel::BlobData)
        .field(context.vault_id().as_bytes())
        .u8(DATA_BLOB_KIND)
        .field(context.object_id().as_bytes())
        .field(context.dek_id().as_bytes())
        .field(blob_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::chunk_keys::tests::context;

    #[test]
    fn layout_is_fs_55() {
        let blob_id = BlobId::try_from_bytes([4; 32]).expect("non-zero");
        let aad = data_blob_aad(&context(2), &blob_id);
        let label = b"crypthix/v0/aad/blob-data";
        let mut expected = vec![25u8];
        expected.extend_from_slice(label);
        expected.extend_from_slice(&[0, 0, 0, 1]);
        expected.extend_from_slice(&[1; 16]);
        expected.push(0x01);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&[3; 16]);
        expected.extend_from_slice(&[4; 32]);
        assert_eq!(aad.as_bytes(), expected.as_slice());
    }
}
