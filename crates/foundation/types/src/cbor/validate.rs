//! The structural pass over a CBOR document (FS-08 to FS-11).
//!
//! One iterative pass, with no recursion, checks every rule that does not depend on a schema.
//! Typed reads in [`Decoder`](crate::cbor::Decoder) can then rely on the bytes being canonical
//! and within limits.

use crate::cbor::Limits;
use crate::cbor::head;
use crate::format_error::FormatError;

/// Largest argument of a negative integer: -1 - argument stays at or above -2^63 (FS-09).
const MAX_NEGATIVE_ARGUMENT: u64 = (1 << 63) - 1;
/// Largest argument of a map key, in either sign: keys lie in -2^31 to 2^31 - 1 (FS-09).
const MAX_KEY_ARGUMENT: u64 = (1 << 31) - 1;

/// An open array or map.
struct Frame {
    /// Items still to read; a map entry counts as two.
    remaining: u64,
    /// Whether this is a map, whose items alternate between key and value.
    map: bool,
    /// Byte range of the previous key in a map, for the order check.
    previous_key: Option<(usize, usize)>,
}

/// Checks that `input` is exactly one CBOR item in the deterministic encoding of format 0.
///
/// Items are checked in byte order, so the first item that breaks a rule decides the error
/// (FS-93). At each head the order is: the head itself (`Truncated`, `NonCanonical`), then a
/// tag or simple value (`NonCanonical`), then the map-key rules (`Schema`), then the value's own
/// rules and limits.
pub(crate) fn document(input: &[u8], limits: &Limits) -> Result<(), FormatError> {
    if input.len() > limits.max_document_len() {
        return Err(FormatError::Limit);
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut position = 0usize;
    let mut total_items = 0u64;
    loop {
        let start = position;
        let item = head::read(input, position)?;
        position = position.checked_add(item.len).ok_or(FormatError::Limit)?;
        total_items += 1;
        if total_items > limits.max_total_items() {
            return Err(FormatError::Limit);
        }
        let remaining = input.get(position..).ok_or(FormatError::Truncated)?;
        let remaining_bytes = u64::try_from(remaining.len()).map_err(|_| FormatError::Limit)?;

        // Tags and simple values are wrong in any position, so they come before key checks.
        match item.major {
            head::TAG => return Err(FormatError::NonCanonical),
            // Only false, true and null (FS-08).
            head::SIMPLE
                if !matches!(item.argument, head::FALSE | head::TRUE | head::NULL)
                    || item.len != 1 =>
            {
                return Err(FormatError::NonCanonical);
            }
            _ => {}
        }
        let is_key = stack
            .last()
            .is_some_and(|frame| frame.map && frame.remaining.is_multiple_of(2));
        if is_key {
            check_key(item)?;
        }

        match item.major {
            head::NEGATIVE => {
                if item.argument > MAX_NEGATIVE_ARGUMENT {
                    return Err(FormatError::Schema);
                }
            }
            head::BYTES | head::TEXT => {
                // A declared length above the bytes left is `Limit`, checked at the head (FS-11).
                if item.argument > limits.max_string_len() || item.argument > remaining_bytes {
                    return Err(FormatError::Limit);
                }
                let len = usize::try_from(item.argument).map_err(|_| FormatError::Limit)?;
                let payload = remaining.get(..len).ok_or(FormatError::Limit)?;
                if item.major == head::TEXT {
                    let text = std::str::from_utf8(payload).map_err(|_| FormatError::Schema)?;
                    check_text(text)?;
                }
                position = position.checked_add(len).ok_or(FormatError::Limit)?;
            }
            head::ARRAY | head::MAP => {
                if stack.len() >= limits.max_depth() || item.argument > limits.max_container_len() {
                    return Err(FormatError::Limit);
                }
                let map = item.major == head::MAP;
                let slots = if map {
                    item.argument.checked_mul(2).ok_or(FormatError::Limit)?
                } else {
                    item.argument
                };
                // Every item takes at least one byte, so a count above the bytes left can never
                // be satisfied; rejecting it at the head also bounds pre-allocation (FS-11).
                if slots > remaining_bytes {
                    return Err(FormatError::Limit);
                }
                consume_slot(&mut stack, input, start, position, /* is_key */ false)?;
                if slots > 0 {
                    stack.push(Frame {
                        remaining: slots,
                        map,
                        previous_key: None,
                    });
                }
                pop_finished(&mut stack);
                if stack.is_empty() {
                    break;
                }
                continue;
            }
            _ => {}
        }
        consume_slot(&mut stack, input, start, position, is_key)?;
        pop_finished(&mut stack);
        if stack.is_empty() {
            break;
        }
    }
    if position == input.len() {
        Ok(())
    } else {
        Err(FormatError::TrailingBytes)
    }
}

/// Records that an item filled a slot of the innermost container, and checks key order.
fn consume_slot(
    stack: &mut [Frame],
    input: &[u8],
    start: usize,
    end: usize,
    is_key: bool,
) -> Result<(), FormatError> {
    let Some(frame) = stack.last_mut() else {
        return Ok(());
    };
    if is_key {
        // Heads are already in shortest form, so comparing the raw key bytes gives exactly the
        // bytewise order of RFC 8949 section 4.2.1. Equal means a duplicate key.
        let key = input.get(start..end).ok_or(FormatError::Truncated)?;
        if let Some((previous_start, previous_end)) = frame.previous_key {
            let previous = input
                .get(previous_start..previous_end)
                .ok_or(FormatError::Truncated)?;
            if previous >= key {
                return Err(FormatError::NonCanonical);
            }
        }
        frame.previous_key = Some((start, end));
    }
    frame.remaining = frame.remaining.saturating_sub(1);
    Ok(())
}

/// Closes every container whose items are all read.
fn pop_finished(stack: &mut Vec<Frame>) {
    while stack.last().is_some_and(|frame| frame.remaining == 0) {
        stack.pop();
    }
}

/// Map keys are integers in −2^31 to 2^31 − 1 (FS-09).
fn check_key(item: head::Head) -> Result<(), FormatError> {
    let in_range =
        matches!(item.major, head::UNSIGNED | head::NEGATIVE) && item.argument <= MAX_KEY_ARGUMENT;
    if in_range {
        Ok(())
    } else {
        Err(FormatError::Schema)
    }
}

/// Text strings carry no control or bidirectional formatting characters (FS-10).
pub(crate) fn check_text(text: &str) -> Result<(), FormatError> {
    let forbidden = |c: char| {
        c.is_control()
            || matches!(
                c,
                '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}'
            )
            || matches!(c, '\u{2066}'..='\u{2069}')
    };
    if text.chars().any(forbidden) {
        Err(FormatError::Schema)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(bytes: &[u8]) -> Result<(), FormatError> {
        document(bytes, &Limits::FORMAT_0)
    }

    fn nested_arrays(depth: usize) -> Vec<u8> {
        let mut bytes = vec![0x81; depth - 1];
        bytes.push(0x80);
        bytes
    }

    #[test]
    fn accepts_canonical_items() {
        for bytes in [
            &[0x00][..],
            &[0x17],
            &[0x18, 0x18],
            &[0x20],
            &[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0x43, 1, 2, 3],
            &[0x62, b'h', b'i'],
            &[0x80],
            &[0x82, 0x01, 0x82, 0x02, 0x03],
            &[0xa0],
            &[0xa2, 0x18, 0x18, 0xf4, 0x20, 0xf6],
            &[0xf4],
            &[0xf5],
            &[0xf6],
        ] {
            assert_eq!(check(bytes), Ok(()), "{bytes:02x?}");
        }
    }

    #[test]
    fn rejects_non_canonical_items() {
        for bytes in [
            // Non-shortest heads.
            &[0x18, 0x05][..],
            &[0x82, 0x01, 0x18, 0x02],
            // Indefinite length and break.
            &[0x9f, 0xff],
            &[0x5f, 0xff],
            &[0xff],
            // Tags, floats, undefined and other simple values.
            &[0xc0, 0x00],
            &[0xf9, 0x00, 0x00],
            &[0xfa, 0x00, 0x00, 0x00, 0x00],
            &[0xfb, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xf7],
            &[0xf0],
            &[0xf8, 0x20],
            &[0x81, 0xf7],
            // Tags, floats and simple values as map keys are wrong in any position.
            &[0xa1, 0xc0, 0x00, 0x00],
            &[0xa1, 0xf9, 0x3c, 0x00, 0x00],
            &[0xa1, 0xf7, 0x00],
            &[0xa1, 0xf0, 0x00],
            // Key -1 before key 24, a duplicate key, keys in numeric but not bytewise order.
            &[0xa2, 0x20, 0x00, 0x18, 0x18, 0x00],
            &[0xa2, 0x01, 0x00, 0x01, 0x00],
            &[0xa2, 0x02, 0x00, 0x01, 0x00],
        ] {
            assert_eq!(check(bytes), Err(FormatError::NonCanonical), "{bytes:02x?}");
        }
    }

    #[test]
    fn schema_errors() {
        for bytes in [
            // Below -2^63.
            &[0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0][..],
            // Key 2^31, key -2^31 - 1, text key, byte-string key, array key.
            &[0xa1, 0x1a, 0x80, 0x00, 0x00, 0x00, 0x00],
            &[0xa1, 0x3a, 0x80, 0x00, 0x00, 0x00, 0x00],
            &[0xa1, 0x61, b'a', 0x00],
            &[0xa1, 0x40, 0x00],
            &[0xa1, 0x80, 0x00],
            // Booleans and null are valid items but not valid keys.
            &[0xa1, 0xf5, 0x00],
            // Invalid UTF-8, a C0 control, DEL, a C1 control, a bidi override.
            &[0x61, 0x7f],
            &[0x62, 0xc3, 0x28],
            &[0x61, 0x0a],
            &[0x62, 0xc2, 0x85],
            &[0x63, 0xe2, 0x80, 0xae],
        ] {
            assert_eq!(check(bytes), Err(FormatError::Schema), "{bytes:02x?}");
        }
    }

    #[test]
    fn key_range_edges_are_accepted() {
        assert_eq!(check(&[0xa1, 0x1a, 0x7f, 0xff, 0xff, 0xff, 0x00]), Ok(()));
        assert_eq!(check(&[0xa1, 0x3a, 0x7f, 0xff, 0xff, 0xff, 0x00]), Ok(()));
    }

    #[test]
    fn every_bidi_character_is_rejected() {
        for c in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}',
        ] {
            assert_eq!(
                check_text(&format!("a{c}b")),
                Err(FormatError::Schema),
                "{c:?}"
            );
        }
        assert_eq!(check_text("ordinary text, ünïcödé"), Ok(()));
    }

    #[test]
    fn depth_limit() {
        assert_eq!(check(&nested_arrays(8)), Ok(()));
        assert_eq!(check(&nested_arrays(9)), Err(FormatError::Limit));
    }

    #[test]
    fn declared_lengths_over_the_input_are_limits() {
        assert_eq!(check(&[0x45, 1, 2]), Err(FormatError::Limit));
        assert_eq!(check(&[0x83, 0x01]), Err(FormatError::Limit));
        assert_eq!(check(&[0xa2, 0x01, 0x02]), Err(FormatError::Limit));
        assert_eq!(
            check(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(FormatError::Limit)
        );
        // A byte string longer than 16 MiB, rejected before reading it.
        assert_eq!(
            check(&[0x5a, 0x01, 0x00, 0x00, 0x01]),
            Err(FormatError::Limit)
        );
    }

    #[test]
    fn container_and_document_limits() {
        let limits = Limits::FORMAT_0
            .with_max_container_len(2)
            .with_max_total_items(4);
        assert_eq!(document(&[0x82, 0x01, 0x02], &limits), Ok(()));
        assert_eq!(
            document(&[0x83, 0x01, 0x02, 0x03], &limits),
            Err(FormatError::Limit)
        );
        assert_eq!(
            document(&[0x82, 0x82, 0x01, 0x02, 0x82, 0x03, 0x04], &limits),
            Err(FormatError::Limit)
        );
        let limits = Limits::FORMAT_0.with_max_document_len(2);
        assert_eq!(
            document(&[0x82, 0x01, 0x02], &limits),
            Err(FormatError::Limit)
        );
    }

    #[test]
    fn errors_follow_byte_order() {
        // Bad text first, then a non-shortest head: the text decides.
        assert_eq!(
            check(&[0x82, 0x61, 0x00, 0x18, 0x05]),
            Err(FormatError::Schema)
        );
        // Non-shortest head first, then bad text: the head decides.
        assert_eq!(
            check(&[0x82, 0x18, 0x05, 0x61, 0x00]),
            Err(FormatError::NonCanonical)
        );
        // A count above the bytes left is decided at the container head.
        assert_eq!(check(&[0x84, 0x18, 0x05, 0x00]), Err(FormatError::Limit));
    }

    #[test]
    fn deep_maps() {
        let mut depth_8 = [0xa1, 0x00].repeat(7);
        depth_8.push(0xa0);
        assert_eq!(check(&depth_8), Ok(()));
        let mut depth_9 = [0xa1, 0x00].repeat(8);
        depth_9.push(0xa0);
        assert_eq!(check(&depth_9), Err(FormatError::Limit));
    }

    #[test]
    fn huge_limits_do_not_overflow() {
        let limits = Limits::FORMAT_0;
        // A map head declaring 2^64 - 1 entries must not overflow when doubled.
        assert_eq!(
            document(
                &[0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                &limits
            ),
            Err(FormatError::Limit)
        );
    }

    #[test]
    fn exactly_one_item() {
        assert_eq!(check(&[]), Err(FormatError::Truncated));
        assert_eq!(check(&[0x01, 0x02]), Err(FormatError::TrailingBytes));
        assert_eq!(
            check(&[0x82, 0x01, 0x02, 0x03]),
            Err(FormatError::TrailingBytes)
        );
    }
}
