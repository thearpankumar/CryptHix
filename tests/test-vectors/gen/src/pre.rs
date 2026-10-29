//! Preamble bytes and hex literals, written by hand for the vectors.

/// The fields of a 20-byte preamble (format spec section 5.1), any of which a vector may set
/// to a wrong value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Pre {
    pub(crate) typ: u8,
    pub(crate) body_len: u32,
    pub(crate) fmt: u16,
    pub(crate) suite: u16,
    pub(crate) sv: u8,
    pub(crate) flags: u16,
}

/// `"\x89CHX\r\n\x1a\n"`.
pub(crate) const MAGIC: &[u8; 8] = b"\x89CHX\r\n\x1a\n";

impl Pre {
    /// A valid keyring preamble with an empty body.
    pub(crate) const KEYRING: Pre = Pre {
        typ: 0x03,
        body_len: 0,
        fmt: 0,
        suite: 1,
        sv: 1,
        flags: 0,
    };

    /// The preamble bytes: `magic ‖ fmt ‖ suite ‖ typ ‖ sv ‖ flags ‖ body_len`, big-endian.
    pub(crate) fn bytes(self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.fmt.to_be_bytes());
        out.extend_from_slice(&self.suite.to_be_bytes());
        out.push(self.typ);
        out.push(self.sv);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.body_len.to_be_bytes());
        out
    }
}

/// A keyring-default preamble with the given type and body length.
pub(crate) fn pre(typ: u8, body_len: u32) -> Vec<u8> {
    Pre {
        typ,
        body_len,
        ..Pre::KEYRING
    }
    .bytes()
}

/// Decodes a hex literal from the generator source.
///
/// # Panics
///
/// On a malformed literal, which is a bug in this generator, never in its input.
pub(crate) fn h(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd hex literal {hex}");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex literal"))
        .collect()
}

/// The pieces joined into one byte string.
pub(crate) fn cat(pieces: &[&[u8]]) -> Vec<u8> {
    pieces.concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_layout() {
        let expected = concat!(
            "894348580d0a1a0a",
            "0000",
            "0001",
            "03",
            "01",
            "0000",
            "00000102"
        );
        assert_eq!(pre(0x03, 0x0102), h(expected));
    }
}
