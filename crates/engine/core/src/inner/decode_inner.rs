//! Checking an inner plaintext (FS-54).

use crypthix_types::format_error::FormatError;

use crate::inner::{Comp, InnerView};
use crate::limits::{INNER_HEADER_LEN, MAX_PAYLOAD_LEN};
use crate::pad::padme;

/// Checks an opened inner plaintext and returns its compression and payload (FS-54).
///
/// The checks run in this order, and the first failure is the error (FS-93):
/// 1. at least the 6 header bytes (`Padding`);
/// 2. `comp` is 0 or 1 (`Padding`);
/// 3. `rsv` is 0 (`Padding`);
/// 4. `payload_len` is at most 1 MiB (`Limit`), before its length is used for anything;
/// 5. the total length is exactly `padme(6 + payload_len)` (`Padding`);
/// 6. every pad byte is zero (`Padding`).
///
/// # Errors
///
/// [`FormatError::Padding`] or [`FormatError::Limit`] as above.
pub fn decode_inner(inner: &[u8]) -> Result<InnerView<'_>, FormatError> {
    let Some((header, rest)) = inner.split_first_chunk::<INNER_HEADER_LEN>() else {
        return Err(FormatError::Padding);
    };
    let [code, rsv, len @ ..] = *header;
    let comp = Comp::from_code(code).ok_or(FormatError::Padding)?;
    if rsv != 0 {
        return Err(FormatError::Padding);
    }
    let payload_len = u64::from(u32::from_be_bytes(len));
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(FormatError::Limit);
    }
    // At most 6 + 2^20, so the sum and its Padmé length always fit.
    let expected = padme(payload_len + INNER_HEADER_LEN as u64);
    if expected != Some(inner.len() as u64) {
        return Err(FormatError::Padding);
    }
    let payload_len = usize::try_from(payload_len).map_err(|_| FormatError::Limit)?;
    let (payload, pad) = rest
        .split_at_checked(payload_len)
        .ok_or(FormatError::Padding)?;
    if pad.iter().any(|byte| *byte != 0) {
        return Err(FormatError::Padding);
    }
    Ok(InnerView::new(comp, payload))
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::{any, prop_assert_eq, proptest};

    use super::*;
    use crate::inner::encode_inner;

    /// A well-formed inner plaintext of `payload_len` bytes of 0x55, as plain bytes.
    fn inner(comp: u8, payload_len: usize) -> Vec<u8> {
        let total = padme(payload_len as u64 + 6).expect("fits");
        let mut bytes = vec![0u8; usize::try_from(total).expect("fits")];
        bytes[0] = comp;
        let len = u32::try_from(payload_len).expect("fits");
        bytes[2..6].copy_from_slice(&len.to_be_bytes());
        bytes[6..6 + payload_len].fill(0x55);
        bytes
    }

    #[test]
    fn a_well_formed_inner_plaintext_decodes() {
        let bytes = inner(1, 1_000);
        let view = decode_inner(&bytes).expect("well formed");
        assert_eq!(view.comp(), Comp::Zstd);
        assert_eq!(view.payload(), &[0x55; 1_000]);
    }

    #[test]
    fn short_input_is_padding() {
        for len in 0..6 {
            assert_eq!(
                decode_inner(&vec![0; len]).map(|_| ()),
                Err(FormatError::Padding)
            );
        }
        assert!(decode_inner(&[0; 6]).is_ok(), "an empty payload is fine");
    }

    #[test]
    fn unknown_comp_and_reserved_byte_are_padding() {
        let mut bytes = inner(2, 10);
        assert_eq!(decode_inner(&bytes).map(|_| ()), Err(FormatError::Padding));
        bytes[0] = 0;
        bytes[1] = 1;
        assert_eq!(decode_inner(&bytes).map(|_| ()), Err(FormatError::Padding));
    }

    #[test]
    fn payload_len_is_capped_at_one_mib_before_the_length_check() {
        let mut header = vec![0u8, 0];
        header.extend_from_slice(&(1u32 << 20).to_be_bytes());
        // Exactly 2^20 is allowed: only the length is wrong here.
        assert_eq!(decode_inner(&header).map(|_| ()), Err(FormatError::Padding));
        header[2..6].copy_from_slice(&((1u32 << 20) + 1).to_be_bytes());
        assert_eq!(decode_inner(&header).map(|_| ()), Err(FormatError::Limit));
        header[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode_inner(&header).map(|_| ()), Err(FormatError::Limit));
        // A bad comp code is found first.
        header[0] = 9;
        assert_eq!(decode_inner(&header).map(|_| ()), Err(FormatError::Padding));
    }

    #[test]
    #[cfg_attr(miri, ignore = "megabyte buffers are slow under Miri")]
    fn a_full_one_mib_payload_decodes() {
        let bytes = inner(0, 1 << 20);
        let view = decode_inner(&bytes).expect("2^20 is allowed");
        assert_eq!(view.payload().len(), 1 << 20);
    }

    #[test]
    fn the_length_must_be_exactly_padme() {
        let bytes = inner(0, 1_000);
        assert_eq!(bytes.len(), 1_024);
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode_inner(&longer).map(|_| ()), Err(FormatError::Padding));
        assert_eq!(
            decode_inner(&bytes[..1_023]).map(|_| ()),
            Err(FormatError::Padding)
        );
        // Unpadded: header and payload alone.
        assert_eq!(
            decode_inner(&bytes[..1_006]).map(|_| ()),
            Err(FormatError::Padding)
        );
    }

    #[test]
    fn every_pad_byte_must_be_zero() {
        let bytes = inner(0, 1_000);
        for at in [1_006, 1_015, 1_023] {
            let mut bad = bytes.clone();
            bad[at] = 1;
            assert_eq!(
                decode_inner(&bad).map(|_| ()),
                Err(FormatError::Padding),
                "{at}"
            );
        }
    }

    proptest! {
        #[test]
        #[cfg_attr(miri, ignore = "proptest is slow under Miri")]
        fn encode_then_decode_round_trips(payload in vec(any::<u8>(), 0..5_000), zstd in any::<bool>()) {
            let comp = if zstd { Comp::Zstd } else { Comp::Raw };
            let encoded = encode_inner(comp, &payload).expect("encodes");
            prop_assert_eq!(encoded.len() as u64, padme(payload.len() as u64 + 6).expect("fits"));
            let view = decode_inner(&encoded).expect("decodes");
            prop_assert_eq!(view.comp(), comp);
            prop_assert_eq!(view.payload(), payload.as_slice());
        }

        #[test]
        #[cfg_attr(miri, ignore = "proptest is slow under Miri")]
        fn decoding_never_panics_and_accepts_only_its_own_encoding(bytes in vec(any::<u8>(), 0..300)) {
            if let Ok(view) = decode_inner(&bytes) {
                let encoded = encode_inner(view.comp(), view.payload()).expect("encodes");
                prop_assert_eq!(encoded.as_slice(), bytes.as_slice());
            }
        }
    }
}
