//! Checking an inner plaintext (FS-54).

use crypthix_types::format_error::FormatError;

use crate::inner::{Comp, InnerView};
use crate::limits::{INNER_HEADER_LEN, MAX_PAYLOAD_LEN};
use crate::pad;

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
    let expected = pad::padme(payload_len + INNER_HEADER_LEN as u64);
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
    use proptest::prelude::{
        Strategy, TestCaseError, any, prop_assert, prop_assert_eq, prop_oneof, proptest,
    };
    use proptest::sample::Index;

    use super::*;
    use crate::inner;
    use crate::test_data::{any_byte, bytes};

    /// A well-formed inner plaintext of `payload_len` bytes of 0x55, as plain bytes.
    fn inner(comp: u8, payload_len: usize) -> Vec<u8> {
        let total = pad::padme(payload_len as u64 + 6).expect("fits");
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

    /// One change to a valid inner plaintext.
    #[derive(Clone, Debug)]
    enum Mutation {
        /// A byte anywhere XOR-ed with a non-zero value.
        Flip(Index, u8),
        /// One byte more (a zero) or one fewer.
        Resize(bool),
        /// The `comp` byte set to any value, its own included.
        Comp(u8),
        /// The `rsv` byte set to any value, zero included.
        Rsv(u8),
        /// `payload_len` moved by this much, wrapping, with the bytes left as they are.
        PayloadLen(i32),
        /// `payload_len` set to any value.
        AnyPayloadLen(u32),
        /// The bytes cut to a shorter length.
        Truncate(Index),
        /// Bytes appended.
        Append(Vec<u8>),
    }

    fn mutation() -> impl Strategy<Value = Mutation> {
        prop_oneof![
            (any::<Index>(), 1u8..).prop_map(|(at, xor)| Mutation::Flip(at, xor)),
            any::<bool>().prop_map(Mutation::Resize),
            any::<u8>().prop_map(Mutation::Comp),
            any::<u8>().prop_map(Mutation::Rsv),
            prop_oneof![-2i32..=2, -8_192i32..8_192].prop_map(Mutation::PayloadLen),
            any::<u32>().prop_map(Mutation::AnyPayloadLen),
            any::<Index>().prop_map(Mutation::Truncate),
            vec(any::<u8>(), 1..16).prop_map(Mutation::Append),
        ]
    }

    fn apply(bytes: &mut Vec<u8>, mutation: &Mutation) {
        match mutation {
            Mutation::Flip(at, xor) => {
                let at = at.index(bytes.len());
                bytes[at] ^= xor;
            }
            Mutation::Resize(true) => bytes.push(0),
            Mutation::Resize(false) => {
                bytes.pop();
            }
            Mutation::Comp(comp) => bytes[0] = *comp,
            Mutation::Rsv(rsv) => bytes[1] = *rsv,
            Mutation::PayloadLen(delta) => {
                let len = u32::from_be_bytes(bytes[2..6].try_into().expect("four bytes"));
                bytes[2..6].copy_from_slice(&len.wrapping_add_signed(*delta).to_be_bytes());
            }
            Mutation::AnyPayloadLen(len) => bytes[2..6].copy_from_slice(&len.to_be_bytes()),
            Mutation::Truncate(at) => {
                let len = at.index(bytes.len());
                bytes.truncate(len);
            }
            Mutation::Append(extra) => bytes.extend_from_slice(extra),
        }
    }

    /// The one inner plaintext `bytes` could be: the encoding of the `comp` and payload its
    /// header names, if those are valid; `None` if no encoding starts like `bytes`.
    fn candidate(bytes: &[u8]) -> Option<(Comp, Vec<u8>, Vec<u8>)> {
        let header = bytes.get(..6)?;
        let comp = match header[0] {
            0 => Comp::Raw,
            1 => Comp::Zstd,
            _ => return None,
        };
        let len = usize::try_from(u32::from_be_bytes(header[2..6].try_into().ok()?)).ok()?;
        let payload = bytes.get(6..6_usize.checked_add(len)?)?;
        let encoded = inner::encode_inner(comp, payload).ok()?;
        Some((comp, payload.to_vec(), encoded.to_vec()))
    }

    /// Checks `decode_inner` against [`candidate`]: it accepts exactly the bytes that are the
    /// encoding of what they decode to, and fails otherwise with `Limit` when a valid `comp`
    /// and `rsv` precede a `payload_len` over 1 MiB, else with `Padding`.
    fn check_canonical(bytes: &[u8]) -> Result<(), TestCaseError> {
        let canonical = candidate(bytes).filter(|(_, _, encoded)| encoded == bytes);
        match (decode_inner(bytes), canonical) {
            (Ok(view), Some((comp, payload, _))) => {
                prop_assert_eq!(view.comp(), comp);
                prop_assert_eq!(view.payload(), payload.as_slice());
            }
            (Ok(_), None) => prop_assert!(false, "accepted bytes that are not an encoding"),
            (Err(error), Some(_)) => prop_assert!(false, "refused an encoding: {:?}", error),
            (Err(error), None) => {
                let over_cap = bytes.len() >= 6
                    && bytes[0] <= 1
                    && bytes[1] == 0
                    && u32::from_be_bytes(bytes[2..6].try_into().expect("four bytes")) > 1 << 20;
                let expected = if over_cap {
                    FormatError::Limit
                } else {
                    FormatError::Padding
                };
                prop_assert_eq!(error, expected);
            }
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn encode_then_decode_round_trips(payload in bytes(0..5_000, any_byte), zstd in any::<bool>()) {
            let comp = if zstd { Comp::Zstd } else { Comp::Raw };
            let encoded = inner::encode_inner(comp, &payload).expect("encodes");
            prop_assert_eq!(encoded.len() as u64, pad::padme(payload.len() as u64 + 6).expect("fits"));
            let view = decode_inner(&encoded).expect("decodes");
            prop_assert_eq!(view.comp(), comp);
            prop_assert_eq!(view.payload(), payload.as_slice());
        }

        #[test]
        fn a_changed_encoding_is_accepted_only_if_it_is_still_an_encoding(
            payload in bytes(0..3_000, any_byte),
            zstd in any::<bool>(),
            mutation in mutation(),
        ) {
            let comp = if zstd { Comp::Zstd } else { Comp::Raw };
            let mut bytes = inner::encode_inner(comp, &payload).expect("encodes").to_vec();
            check_canonical(&bytes)?;
            let len = bytes.len();
            apply(&mut bytes, &mutation);
            check_canonical(&bytes)?;
            // Where the outcome follows from the change alone, check it directly too. A new
            // `payload_len` can still name a valid encoding, of a payload ending in zeros or
            // with fewer bytes, so only [`check_canonical`] judges those.
            let keeps = match &mutation {
                Mutation::Flip(at, _) => match at.index(len) {
                    0 => Some(bytes[0] <= 1),
                    1 => Some(false),
                    2..6 => None,
                    at => Some(at < 6 + payload.len()),
                },
                Mutation::Comp(code) => Some(*code <= 1),
                Mutation::Rsv(rsv) => Some(*rsv == 0),
                Mutation::PayloadLen(0) => Some(true),
                Mutation::AnyPayloadLen(new) if *new as usize == payload.len() => Some(true),
                Mutation::PayloadLen(_) | Mutation::AnyPayloadLen(_) => None,
                Mutation::Resize(_) | Mutation::Truncate(_) | Mutation::Append(_) => Some(false),
            };
            if let Some(keeps) = keeps {
                prop_assert_eq!(decode_inner(&bytes).is_ok(), keeps, "{:?}", mutation);
            }
        }

        #[test]
        fn arbitrary_bytes_decode_only_if_they_are_an_encoding(bytes in vec(any::<u8>(), 0..300)) {
            check_canonical(&bytes)?;
        }
    }
}
