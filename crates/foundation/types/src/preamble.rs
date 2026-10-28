//! The 20-byte preamble every file starts with (format spec section 5.1).

use std::cmp::Ordering;

use crate::format_error::FormatError;
use crate::registry::{FileType, FormatVersion, NestedType, SuiteId};

/// The clear 20-byte preamble at the start of every file.
///
/// ```text
/// magic[8] ‖ fmt u16be ‖ suite u16be ‖ typ u8 ‖ sv u8 ‖ flags u16be ‖ body_len u32be
/// ```
///
/// # Examples
///
/// ```
/// use crypthix_types::preamble::Preamble;
/// use crypthix_types::registry::FileType;
///
/// let preamble = Preamble::new(FileType::Keyring, 3)?;
/// let mut file = preamble.to_bytes().to_vec();
/// file.extend_from_slice(b"abc");
/// let (parsed, body) = Preamble::parse(&file)?;
/// assert_eq!(parsed, preamble);
/// assert_eq!(body, b"abc");
/// # Ok::<(), crypthix_types::format_error::FormatError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Preamble {
    format: FormatVersion,
    suite: SuiteId,
    file_type: FileType,
    body_len: u32,
}

impl Preamble {
    /// Length of the preamble in bytes.
    pub const LEN: usize = 20;

    /// `"\x89CHX\r\n\x1a\n"`: high bit, name, CR LF, ^Z, LF, as in PNG.
    pub const MAGIC: [u8; 8] = *b"\x89CHX\r\n\x1a\n";

    /// A format 0 preamble for a body of `body_len` bytes.
    ///
    /// # Errors
    ///
    /// [`FormatError::Limit`] if `body_len` exceeds the cap for `file_type` (FS-07).
    pub const fn new(file_type: FileType, body_len: u32) -> Result<Self, FormatError> {
        if body_len > file_type.max_body_len() {
            return Err(FormatError::Limit);
        }
        Ok(Self {
            format: FormatVersion::V0,
            suite: SuiteId::SUITE_0001,
            file_type,
            body_len,
        })
    }

    /// Parses a whole file into its preamble and body.
    ///
    /// The checks run in this order, and the first failure is returned (FS-93): magic
    /// (`Magic`), length of the preamble (`Truncated`), format (`UnsupportedFormat`), suite
    /// (`UnsupportedSuite`), type (`UnknownType`), struct version (`UnsupportedStruct`), flags
    /// (`Flags`), `body_len` against the type's cap (`Limit`), then the actual body length
    /// (`Truncated` or `TrailingBytes`).
    ///
    /// # Errors
    ///
    /// The [`FormatError`] of the first failing check above.
    pub fn parse(file: &[u8]) -> Result<(Self, &[u8]), FormatError> {
        let magic_len = file.len().min(Self::MAGIC.len());
        if file[..magic_len] != Self::MAGIC[..magic_len] {
            return Err(FormatError::Magic);
        }
        let Some((head, body)) = file.split_first_chunk::<{ Self::LEN }>() else {
            return Err(FormatError::Truncated);
        };
        let format = FormatVersion::try_from_code(u16::from_be_bytes([head[8], head[9]]))?;
        let suite = SuiteId::try_from_code(u16::from_be_bytes([head[10], head[11]]))?;
        let file_type = FileType::try_from_code(head[12])?;
        if head[13] != FileType::STRUCT_VERSION {
            return Err(FormatError::UnsupportedStruct);
        }
        if u16::from_be_bytes([head[14], head[15]]) != 0 {
            return Err(FormatError::Flags);
        }
        let body_len = u32::from_be_bytes([head[16], head[17], head[18], head[19]]);
        if body_len > file_type.max_body_len() {
            return Err(FormatError::Limit);
        }
        let declared = usize::try_from(body_len).map_err(|_| FormatError::Limit)?;
        match body.len().cmp(&declared) {
            Ordering::Less => Err(FormatError::Truncated),
            Ordering::Greater => Err(FormatError::TrailingBytes),
            Ordering::Equal => Ok((
                Self {
                    format,
                    suite,
                    file_type,
                    body_len,
                },
                body,
            )),
        }
    }

    /// The 20 preamble bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; Self::LEN] {
        let context = Self::context_bytes(self.format, self.suite, self.file_type.code());
        let body_len = self.body_len.to_be_bytes();
        let mut out = [0u8; Self::LEN];
        let mut index = 0;
        while index < 16 {
            out[index] = context[index];
            index += 1;
        }
        out[16] = body_len[0];
        out[17] = body_len[1];
        out[18] = body_len[2];
        out[19] = body_len[3];
        out
    }

    /// `preamble[0..16]`, the context of signature inputs and of the shard-header AAD (FS-13).
    #[must_use]
    pub const fn context(&self) -> [u8; 16] {
        Self::context_bytes(self.format, self.suite, self.file_type.code())
    }

    /// The synthetic preamble context of an envelope nested inside another structure (FS-13).
    #[must_use]
    pub const fn synthetic_context(nested: NestedType) -> [u8; 16] {
        Self::context_bytes(FormatVersion::V0, SuiteId::SUITE_0001, nested.code())
    }

    /// The format version.
    #[must_use]
    pub const fn format(&self) -> FormatVersion {
        self.format
    }

    /// The suite.
    #[must_use]
    pub const fn suite(&self) -> SuiteId {
        self.suite
    }

    /// The file type.
    #[must_use]
    pub const fn file_type(&self) -> FileType {
        self.file_type
    }

    /// The number of bytes after the preamble.
    #[must_use]
    pub const fn body_len(&self) -> u32 {
        self.body_len
    }

    const fn context_bytes(format: FormatVersion, suite: SuiteId, type_code: u8) -> [u8; 16] {
        let format = format.code().to_be_bytes();
        let suite = suite.code().to_be_bytes();
        let mut out = [0u8; 16];
        let mut index = 0;
        while index < 8 {
            out[index] = Self::MAGIC[index];
            index += 1;
        }
        out[8] = format[0];
        out[9] = format[1];
        out[10] = suite[0];
        out[11] = suite[1];
        out[12] = type_code;
        out[13] = FileType::STRUCT_VERSION;
        // out[14..16] are the flags, zero in format 0.
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(head: [u8; 20], body: &[u8]) -> Vec<u8> {
        let mut file = head.to_vec();
        file.extend_from_slice(body);
        file
    }

    fn keyring_head(body_len: u32) -> [u8; 20] {
        Preamble::new(FileType::Keyring, body_len)
            .expect("within cap")
            .to_bytes()
    }

    #[test]
    fn layout_is_exact() {
        let head = keyring_head(0x0102);
        assert_eq!(
            head,
            [
                0x89, 0x43, 0x48, 0x58, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x03, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
            ]
        );
    }

    #[test]
    fn round_trip() {
        let bytes = file(keyring_head(2), b"hi");
        let (preamble, body) = Preamble::parse(&bytes).expect("valid file");
        assert_eq!(preamble.file_type(), FileType::Keyring);
        assert_eq!(preamble.body_len(), 2);
        assert_eq!(body, b"hi");
        assert_eq!(preamble.context(), bytes[..16]);
    }

    #[test]
    fn magic() {
        assert_eq!(Preamble::parse(b""), Err(FormatError::Truncated));
        assert_eq!(Preamble::parse(b"\x89CH"), Err(FormatError::Truncated));
        assert_eq!(Preamble::parse(b"\x89CHY"), Err(FormatError::Magic));
        let mut head = keyring_head(0);
        head[3] = b'x';
        assert_eq!(Preamble::parse(&head), Err(FormatError::Magic));
    }

    #[test]
    fn short_preamble_is_truncated() {
        assert_eq!(
            Preamble::parse(&keyring_head(0)[..19]),
            Err(FormatError::Truncated)
        );
    }

    #[test]
    fn version_suite_type_and_struct() {
        let mut head = keyring_head(0);
        head[9] = 1;
        assert_eq!(Preamble::parse(&head), Err(FormatError::UnsupportedFormat));
        let mut head = keyring_head(0);
        head[11] = 2;
        assert_eq!(Preamble::parse(&head), Err(FormatError::UnsupportedSuite));
        for code in [0x00, 0x11, 0x20, 0xF0] {
            let mut head = keyring_head(0);
            head[12] = code;
            assert_eq!(Preamble::parse(&head), Err(FormatError::UnknownType));
        }
        let mut head = keyring_head(0);
        head[13] = 2;
        assert_eq!(Preamble::parse(&head), Err(FormatError::UnsupportedStruct));
    }

    #[test]
    fn flags_must_be_zero() {
        let mut head = keyring_head(0);
        head[15] = 1;
        assert_eq!(Preamble::parse(&head), Err(FormatError::Flags));
    }

    #[test]
    fn body_length() {
        assert_eq!(
            Preamble::parse(&file(keyring_head(3), b"ab")),
            Err(FormatError::Truncated)
        );
        assert_eq!(
            Preamble::parse(&file(keyring_head(1), b"ab")),
            Err(FormatError::TrailingBytes)
        );
        let mut head = keyring_head(0);
        head[16..20].copy_from_slice(&4097u32.to_be_bytes());
        assert_eq!(Preamble::parse(&head), Err(FormatError::Limit));
        assert_eq!(
            Preamble::new(FileType::Keyring, 4097),
            Err(FormatError::Limit)
        );
    }

    #[test]
    fn checks_run_in_order() {
        // Every field is wrong; each fix reveals the next error in the documented order.
        let mut head = [0xFFu8; 20];
        head[..8].copy_from_slice(&Preamble::MAGIC);
        let steps: [(usize, &[u8], FormatError); 5] = [
            (8, &[0, 0], FormatError::UnsupportedFormat),
            (10, &[0, 1], FormatError::UnsupportedSuite),
            (12, &[0x03], FormatError::UnknownType),
            (13, &[1], FormatError::UnsupportedStruct),
            (14, &[0, 0], FormatError::Flags),
        ];
        for (offset, fix, error) in steps {
            assert_eq!(Preamble::parse(&head), Err(error));
            head[offset..offset + fix.len()].copy_from_slice(fix);
        }
        assert_eq!(Preamble::parse(&head), Err(FormatError::Limit));
    }

    #[test]
    fn synthetic_context_uses_the_nested_code() {
        let context = Preamble::synthetic_context(NestedType::Manifest);
        assert_eq!(context[..8], Preamble::MAGIC);
        assert_eq!(
            context[8..],
            [0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x00, 0x00]
        );
    }
}
