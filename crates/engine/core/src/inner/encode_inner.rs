//! Building an inner plaintext (FS-54).

use crypthix_crypto::secure_mem::SecretBuf;
use crypthix_types::format_error::FormatError;

use crate::error::WriteError;
use crate::inner::Comp;
use crate::limits::{INNER_HEADER_LEN, MAX_PAYLOAD_LEN};
use crate::pad::padme;

/// The inner plaintext of `payload`: `comp ‖ 0 ‖ u32be(len) ‖ payload ‖ zero pad`, padded to
/// `padme(6 + len)` bytes (FS-54), in a new buffer of protected memory.
///
/// ```
/// use crypthix_core::inner::{self, Comp};
///
/// let inner = inner::encode_inner(Comp::Raw, b"chunk")?;
/// assert_eq!(inner.len(), 12);
/// assert_eq!(&inner[..6], &[0, 0, 0, 0, 0, 5]);
/// let view = inner::decode_inner(&inner)?;
/// assert_eq!(view.payload(), b"chunk");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// - [`WriteError::Format`] with `Limit` if `payload` is longer than 1 MiB.
/// - [`WriteError::Memory`] if protected memory cannot be allocated for the result.
pub fn encode_inner(comp: Comp, payload: &[u8]) -> Result<SecretBuf, WriteError> {
    let payload_len = payload.len() as u64;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(FormatError::Limit.into());
    }
    let header_len = u32::try_from(payload.len()).map_err(|_| FormatError::Limit)?;
    let total = padme(payload_len + INNER_HEADER_LEN as u64)
        .and_then(|total| usize::try_from(total).ok())
        .ok_or(FormatError::Limit)?;
    let mut inner = SecretBuf::try_zeroed(total)?;
    // `padme(6 + len) >= 6 + len`, so both splits succeed; failing instead keeps this
    // panic-free.
    let (header, rest) = inner
        .as_mut_slice()
        .split_first_chunk_mut::<INNER_HEADER_LEN>()
        .ok_or(FormatError::Limit)?;
    let [code, rsv, len @ ..] = header;
    *code = comp.code();
    *rsv = 0;
    *len = header_len.to_be_bytes();
    rest.get_mut(..payload.len())
        .ok_or(FormatError::Limit)?
        .copy_from_slice(payload);
    Ok(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_header_payload_then_zero_pad() {
        let inner = encode_inner(Comp::Zstd, &[0xAB; 1_000]).expect("encodes");
        assert_eq!(inner.len(), 1_024);
        assert_eq!(&inner[..6], &[1, 0, 0, 0, 0x03, 0xE8]);
        assert!(inner[6..1_006].iter().all(|byte| *byte == 0xAB));
        assert!(inner[1_006..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn an_empty_payload_is_just_the_header() {
        let inner = encode_inner(Comp::Raw, &[]).expect("encodes");
        assert_eq!(inner.as_slice(), &[0; 6]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "megabyte buffers are slow under Miri")]
    fn payloads_up_to_one_mib_and_no_longer() {
        let largest = vec![7u8; 1 << 20];
        let inner = encode_inner(Comp::Raw, &largest).expect("1 MiB is allowed");
        assert_eq!(inner.len(), (1 << 20) + (1 << 15));
        let over = vec![7u8; (1 << 20) + 1];
        assert_eq!(
            encode_inner(Comp::Raw, &over).map(|_| ()),
            Err(WriteError::Format(FormatError::Limit))
        );
    }
}
