//! The inner plaintext of a data blob on hostile input (FS-54).
//!
//! An inner plaintext has exactly one encoding for each `(comp, payload)`, so anything the
//! decoder accepts must come back byte for byte when it is encoded again.

use crypthix_core::inner;
use crypthix_core::limits::{INNER_HEADER_LEN, MAX_PAYLOAD_LEN};
use crypthix_types::format_error::FormatError;

/// Decodes `data` as an inner plaintext.
///
/// # Panics
///
/// If an accepted input does not re-encode to itself, or the error is not `Padding` or
/// `Limit`, or `Limit` is given for anything but a well-formed header whose `payload_len` is
/// over 1 MiB, or such a header gives anything else.
pub fn inner_plaintext(data: &[u8]) {
    // `comp` 0 or 1 and `rsv` 0 with `payload_len` over the cap: the only `Limit` (FS-54).
    let over_cap = match data.split_first_chunk::<INNER_HEADER_LEN>() {
        Some(([comp, 0, len @ ..], _)) if *comp <= 1 => {
            u64::from(u32::from_be_bytes(*len)) > MAX_PAYLOAD_LEN
        }
        _ => false,
    };
    match inner::decode_inner(data) {
        Ok(view) => {
            let encoded =
                inner::encode_inner(view.comp(), view.payload()).expect("a decoded payload fits");
            assert_eq!(
                encoded.as_slice(),
                data,
                "an inner plaintext that is not the encoding of its own fields was accepted"
            );
        }
        Err(FormatError::Limit) => assert!(over_cap, "Limit for a payload_len within the cap"),
        Err(FormatError::Padding) => assert!(!over_cap, "Padding for a payload_len over the cap"),
        Err(other) => panic!("an inner plaintext gave {other:?}; only Padding and Limit exist"),
    }
}
