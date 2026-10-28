//! Lowercase hex encoding and strict decoding for IDs and store names.

use std::fmt;

use crate::id::ParseIdError;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Writes `bytes` as lowercase hex.
pub(crate) fn write_lower(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        let pair = [
            DIGITS[usize::from(byte >> 4)],
            DIGITS[usize::from(byte & 0x0f)],
        ];
        for digit in pair {
            fmt::Write::write_char(f, char::from(digit))?;
        }
    }
    Ok(())
}

/// Decodes exactly `N` bytes from lowercase hex of length `2 * N`.
pub(crate) fn decode_lower<const N: usize>(text: &str) -> Result<[u8; N], ParseIdError> {
    let digits = text.as_bytes();
    if digits.len() != 2 * N {
        return Err(ParseIdError::Length);
    }
    let mut out = [0u8; N];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, pair) in out.iter_mut().zip(pairs) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// Whether `text` is non-empty and consists only of hex digits of either case.
pub(crate) fn is_hex_shaped(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn nibble(digit: u8) -> Result<u8, ParseIdError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(ParseIdError::NotLowercaseHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Hex<'a>(&'a [u8]);

    impl fmt::Display for Hex<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_lower(self.0, f)
        }
    }

    #[test]
    fn round_trip() {
        let bytes = [0x00, 0x09, 0xab, 0xff];
        let text = Hex(&bytes).to_string();
        assert_eq!(text, "0009abff");
        assert_eq!(decode_lower::<4>(&text), Ok(bytes));
    }

    #[test]
    fn rejects_uppercase_and_bad_lengths() {
        assert_eq!(
            decode_lower::<2>("ABCD"),
            Err(ParseIdError::NotLowercaseHex)
        );
        assert_eq!(decode_lower::<2>("abc"), Err(ParseIdError::Length));
        assert_eq!(decode_lower::<2>("abcdef"), Err(ParseIdError::Length));
        assert_eq!(
            decode_lower::<2>("abcg"),
            Err(ParseIdError::NotLowercaseHex)
        );
    }

    #[test]
    fn hex_shape() {
        assert!(is_hex_shaped("ABcd09"), "either case is hex-shaped");
        assert!(!is_hex_shaped(""), "empty text is not hex-shaped");
        assert!(!is_hex_shaped("set-1"), "a prefix is not hex");
    }
}
