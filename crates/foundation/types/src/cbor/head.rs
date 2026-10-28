//! CBOR item heads: the initial byte and its argument (RFC 8949 section 3).

use crate::format_error::FormatError;

/// Major type 0: unsigned integer.
pub(crate) const UNSIGNED: u8 = 0;
/// Major type 1: negative integer.
pub(crate) const NEGATIVE: u8 = 1;
/// Major type 2: byte string.
pub(crate) const BYTES: u8 = 2;
/// Major type 3: text string.
pub(crate) const TEXT: u8 = 3;
/// Major type 4: array.
pub(crate) const ARRAY: u8 = 4;
/// Major type 5: map.
pub(crate) const MAP: u8 = 5;
/// Major type 6: tag.
pub(crate) const TAG: u8 = 6;
/// Major type 7: simple values and floats.
pub(crate) const SIMPLE: u8 = 7;

/// The simple value `false`.
pub(crate) const FALSE: u64 = 20;
/// The simple value `true`.
pub(crate) const TRUE: u64 = 21;
/// The simple value `null`.
pub(crate) const NULL: u64 = 22;

/// Additional information: a 1-byte argument follows.
const INFO_U8: u8 = 0x18;
/// Additional information: a 2-byte argument follows.
const INFO_U16: u8 = 0x19;
/// Additional information: a 4-byte argument follows.
const INFO_U32: u8 = 0x1a;
/// Additional information: an 8-byte argument follows.
const INFO_U64: u8 = 0x1b;

/// A decoded head.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Head {
    /// The major type, 0 to 7.
    pub(crate) major: u8,
    /// The argument: a value, a length, an item count or a simple value.
    pub(crate) argument: u64,
    /// Length of the head in bytes, 1 to 9.
    pub(crate) len: usize,
}

/// Reads the head at `input[position..]` and checks that it is in shortest form.
///
/// Indefinite lengths, the break code and reserved additional information values are
/// `NonCanonical` (FS-08); a head cut short is `Truncated`.
pub(crate) fn read(input: &[u8], position: usize) -> Result<Head, FormatError> {
    let Some(&initial) = input.get(position) else {
        return Err(FormatError::Truncated);
    };
    let major = initial >> 5;
    let info = initial & 0x1f;
    let (argument, len) = match info {
        0..=23 => (u64::from(info), 1),
        INFO_U8..=INFO_U64 => {
            let width = 1usize << (info - INFO_U8);
            let bytes = position
                .checked_add(1)
                .and_then(|first| input.get(first..)?.get(..width))
                .ok_or(FormatError::Truncated)?;
            let argument = bytes
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
            // Shortest form: the argument must need this width (RFC 8949 section 4.2.1). A
            // one-byte argument below 24 must be in the initial byte, except for simple values,
            // where 24..32 are reserved and rejected later anyway.
            let minimum: u64 = match info {
                INFO_U8 => 24,
                INFO_U16 => 0x100,
                INFO_U32 => 0x1_0000,
                _ => 0x1_0000_0000,
            };
            if argument < minimum {
                return Err(FormatError::NonCanonical);
            }
            (argument, 1 + width)
        }
        _ => return Err(FormatError::NonCanonical),
    };
    Ok(Head {
        major,
        argument,
        len,
    })
}

/// Length in bytes of the item starting at `input[0]`, without checking canonical form beyond
/// the heads. Used on bytes that were already validated or that this crate encoded.
pub(crate) fn item_len(input: &[u8]) -> Result<usize, FormatError> {
    let mut position = 0usize;
    let mut pending: u64 = 1;
    while pending > 0 {
        let head = read(input, position)?;
        position = position.checked_add(head.len).ok_or(FormatError::Limit)?;
        pending -= 1;
        match head.major {
            BYTES | TEXT => {
                let len = usize::try_from(head.argument).map_err(|_| FormatError::Limit)?;
                position = position.checked_add(len).ok_or(FormatError::Limit)?;
                if position > input.len() {
                    return Err(FormatError::Truncated);
                }
            }
            ARRAY => {
                pending = pending
                    .checked_add(head.argument)
                    .ok_or(FormatError::Limit)?;
            }
            MAP => {
                let slots = head.argument.checked_mul(2).ok_or(FormatError::Limit)?;
                pending = pending.checked_add(slots).ok_or(FormatError::Limit)?;
            }
            // A tag's content would need counting too; format 0 has no tags (FS-08).
            TAG => return Err(FormatError::NonCanonical),
            _ => {}
        }
    }
    Ok(position)
}

/// Appends a head in shortest form.
pub(crate) fn write(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;
    match argument {
        0..=23 => out.push(major | low_byte(argument)),
        24..=0xff => out.extend_from_slice(&[major | INFO_U8, low_byte(argument)]),
        0x100..=0xffff => {
            out.push(major | INFO_U16);
            out.extend_from_slice(&argument.to_be_bytes()[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | INFO_U32);
            out.extend_from_slice(&argument.to_be_bytes()[4..]);
        }
        _ => {
            out.push(major | INFO_U64);
            out.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

fn low_byte(value: u64) -> u8 {
    value.to_be_bytes()[7]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(major: u8, argument: u64) -> Vec<u8> {
        let mut out = Vec::new();
        write(&mut out, major, argument);
        out
    }

    #[test]
    fn writes_shortest_form() {
        assert_eq!(encoded(UNSIGNED, 0), [0x00]);
        assert_eq!(encoded(UNSIGNED, 23), [0x17]);
        assert_eq!(encoded(UNSIGNED, 24), [0x18, 0x18]);
        assert_eq!(encoded(UNSIGNED, 0xff), [0x18, 0xff]);
        assert_eq!(encoded(UNSIGNED, 0x100), [0x19, 0x01, 0x00]);
        assert_eq!(encoded(NEGATIVE, 0x1_0000), [0x3a, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(
            encoded(BYTES, u64::MAX),
            [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn read_round_trips_every_width() {
        for argument in [
            0,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let bytes = encoded(MAP, argument);
            let head = read(&bytes, 0).expect("shortest form");
            assert_eq!(
                (head.major, head.argument, head.len),
                (MAP, argument, bytes.len())
            );
        }
    }

    #[test]
    fn rejects_non_shortest_heads() {
        for bytes in [
            &[0x18, 0x05][..],
            &[0x19, 0x00, 0xff],
            &[0x1a, 0x00, 0x00, 0xff, 0xff],
            &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert_eq!(
                read(bytes, 0),
                Err(FormatError::NonCanonical),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn rejects_reserved_and_indefinite() {
        for initial in [0x1c, 0x1d, 0x1e, 0x5f, 0x7f, 0x9f, 0xbf, 0xff] {
            assert_eq!(
                read(&[initial], 0),
                Err(FormatError::NonCanonical),
                "{initial:#04x}"
            );
        }
    }

    #[test]
    fn item_len_skips_nested_items() {
        assert_eq!(
            item_len(&[0x82, 0x01, 0xa1, 0x01, 0x42, 0xaa, 0xbb, 0xff]),
            Ok(7)
        );
        assert_eq!(item_len(&[0x43, 0x01]), Err(FormatError::Truncated));
        assert_eq!(item_len(&[0x82, 0x01]), Err(FormatError::Truncated));
        assert_eq!(item_len(&[0xc0, 0x01]), Err(FormatError::NonCanonical));
    }

    #[test]
    fn short_argument_is_truncated() {
        assert_eq!(read(&[], 0), Err(FormatError::Truncated));
        assert_eq!(read(&[0x19, 0x01], 0), Err(FormatError::Truncated));
    }
}
