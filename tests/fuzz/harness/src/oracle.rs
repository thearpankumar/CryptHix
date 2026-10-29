//! An independent acceptance check for format 0 CBOR, built on minicbor.
//!
//! minicbor decodes far more than format 0 allows: non-shortest heads, indefinite lengths,
//! tags, floats, unsorted and duplicate keys. The oracle therefore accepts only when minicbor
//! decodes exactly one item, every token is of an allowed kind, and re-encoding the tokens with
//! minicbor's encoder, which always writes the shortest form, gives back the input byte for
//! byte. The remaining rules are written here from the spec text (FS-08 to FS-11), not from
//! `crypthix-types`, so a shared misreading shows up as a disagreement.

use crypthix_types::cbor::Limits;
use minicbor::data::Token;

/// The limits the oracle enforces, mirroring a [`Limits`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OracleLimits {
    /// Largest document in bytes.
    pub max_document_len: usize,
    /// Most containers nested inside each other, counting the outermost.
    pub max_depth: usize,
    /// Most items in an array, or entries in a map.
    pub max_container_len: u64,
    /// Most items in the document, counting every key, value and container.
    pub max_total_items: u64,
    /// Longest byte or text string.
    pub max_string_len: u64,
}

impl OracleLimits {
    /// The format 0 limits, written from FS-11 rather than taken from `crypthix-types`.
    pub const FS_11: Self = Self {
        max_document_len: 16 * 1024 * 1024,
        max_depth: 8,
        max_container_len: 1 << 20,
        max_total_items: 1 << 22,
        max_string_len: 16 * 1024 * 1024,
    };

    /// Small limits, so every limit is reachable at fuzz input sizes.
    pub const SMALL: Self = Self {
        max_document_len: 100,
        max_depth: 4,
        max_container_len: 8,
        max_total_items: 32,
        max_string_len: 16,
    };
}

impl From<&Limits> for OracleLimits {
    fn from(limits: &Limits) -> Self {
        Self {
            max_document_len: limits.max_document_len(),
            max_depth: limits.max_depth(),
            max_container_len: limits.max_container_len(),
            max_total_items: limits.max_total_items(),
            max_string_len: limits.max_string_len(),
        }
    }
}

/// An open array or map.
struct Frame {
    /// Slots still to fill; a map entry takes two.
    remaining: u64,
    map: bool,
    /// The encoded bytes of the previous key, for the order check.
    previous_key: Option<Vec<u8>>,
}

/// Map keys lie in −2^31 to 2^31 − 1 (FS-09).
const KEY_RANGE: std::ops::RangeInclusive<i128> = -(1 << 31)..=(1 << 31) - 1;

/// Text carries no C0 or C1 control, DEL, or bidirectional formatting character (FS-10).
fn forbidden(c: char) -> bool {
    matches!(
        c,
        '\u{0000}'..='\u{001F}'
            | '\u{007F}'..='\u{009F}'
            | '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// The value of an integer token, or `None` for any other token.
fn integer(token: &Token<'_>) -> Option<i128> {
    Some(match *token {
        Token::U8(n) => n.into(),
        Token::U16(n) => n.into(),
        Token::U32(n) => n.into(),
        Token::U64(n) => n.into(),
        Token::I8(n) => n.into(),
        Token::I16(n) => n.into(),
        Token::I32(n) => n.into(),
        Token::I64(n) => n.into(),
        Token::Int(n) => i128::from(n),
        _ => return None,
    })
}

/// Whether `input` is exactly one item of format 0 CBOR within `limits`.
#[must_use]
pub fn accepts(input: &[u8], limits: &OracleLimits) -> bool {
    if input.len() > limits.max_document_len {
        return false;
    }
    let mut decoder = minicbor::Decoder::new(input);
    let mut reencoded: Vec<u8> = Vec::with_capacity(input.len());
    let mut stack: Vec<Frame> = Vec::new();
    let mut items = 0u64;
    {
        let mut tokens = decoder.tokens();
        loop {
            let Some(Ok(token)) = tokens.next() else {
                // Input ended inside the item, or minicbor could not decode it.
                return false;
            };
            items += 1;
            if items > limits.max_total_items {
                return false;
            }
            let Ok(encoded) = minicbor::to_vec(token) else {
                return false;
            };
            let is_key = stack
                .last()
                .is_some_and(|frame| frame.map && frame.remaining.is_multiple_of(2));
            if !allowed(&token, stack.len(), limits) {
                return false;
            }
            if is_key {
                let in_range = integer(&token).is_some_and(|key| KEY_RANGE.contains(&key));
                let frame = stack.last_mut().filter(|_| in_range);
                let Some(frame) = frame else {
                    return false;
                };
                // Keys sort by their encoded bytes, strictly: equal means a duplicate (FS-08).
                if frame
                    .previous_key
                    .as_ref()
                    .is_some_and(|previous| *previous >= encoded)
                {
                    return false;
                }
                frame.previous_key = Some(encoded.clone());
            }
            reencoded.extend_from_slice(&encoded);
            if let Some(frame) = stack.last_mut() {
                frame.remaining -= 1;
            }
            match token {
                Token::Array(n) if n > 0 => stack.push(Frame {
                    remaining: n,
                    map: false,
                    previous_key: None,
                }),
                Token::Map(n) if n > 0 => stack.push(Frame {
                    remaining: n * 2,
                    map: true,
                    previous_key: None,
                }),
                _ => {}
            }
            while stack.last().is_some_and(|frame| frame.remaining == 0) {
                stack.pop();
            }
            if stack.is_empty() {
                break;
            }
        }
    }
    // Exactly one top-level item, and every head in its shortest form.
    decoder.position() == input.len() && reencoded == input
}

/// Whether one token is of a kind and size format 0 allows, at `depth` open containers.
fn allowed(token: &Token<'_>, depth: usize, limits: &OracleLimits) -> bool {
    let string_ok = |len: usize| u64::try_from(len).is_ok_and(|len| len <= limits.max_string_len);
    match *token {
        Token::Bool(_) | Token::Null => true,
        Token::Bytes(bytes) => string_ok(bytes.len()),
        Token::String(text) => string_ok(text.len()) && !text.chars().any(forbidden),
        Token::Array(n) | Token::Map(n) => {
            depth < limits.max_depth && n <= limits.max_container_len
        }
        // Integers down to −2^63 only (FS-09).
        _ => integer(token).is_some_and(|value| value >= i128::from(i64::MIN)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format_0(input: &[u8]) -> bool {
        accepts(input, &OracleLimits::FS_11)
    }

    #[test]
    fn fs_11_is_what_crypthix_types_enforces() {
        assert_eq!(
            OracleLimits::from(&Limits::FORMAT_0),
            OracleLimits::FS_11,
            "Limits::FORMAT_0 must hold the FS-11 values"
        );
    }

    #[test]
    fn accepts_canonical_items() {
        for input in [
            &[0x00][..],
            &[0x18, 0x18],
            &[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0xa2, 0x18, 0x18, 0xf4, 0x20, 0xf6],
            &[0x82, 0x80, 0xa0],
        ] {
            assert!(format_0(input), "canonical input rejected: {input:02x?}");
        }
    }

    #[test]
    fn rejects_what_minicbor_alone_accepts() {
        for input in [
            &[0x18, 0x05][..],                     // non-shortest
            &[0x9f, 0x01, 0xff],                   // indefinite
            &[0xc0, 0x61, 0x30],                   // tag
            &[0xf9, 0x00, 0x00],                   // float
            &[0xa2, 0x20, 0xf4, 0x18, 0x18, 0xf6], // key order
            &[0xa2, 0x01, 0x00, 0x01, 0x01],       // duplicate
            &[0x01, 0x02],                         // trailing
            &[0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0],    // below -2^63
            &[0xa1, 0x1a, 0x80, 0, 0, 0, 0x00],    // key 2^31
            &[0x62, 0xc2, 0x85],                   // C1 control
            &[0xf7],                               // undefined
        ] {
            assert!(
                !format_0(input),
                "non-canonical input accepted: {input:02x?}"
            );
        }
    }

    #[test]
    fn enforces_depth() {
        let mut eight = vec![0x81; 7];
        eight.push(0x80);
        assert!(format_0(&eight), "depth 8 is allowed");
        let mut nine = vec![0x81; 8];
        nine.push(0x80);
        assert!(!format_0(&nine), "depth 9 is not");
    }
}
