//! Validated CBOR documents.

use crate::cbor::validate;
use crate::cbor::{Decoder, Limits};
use crate::format_error::FormatError;

/// A CBOR document that has passed every structural check of FS-08 to FS-11.
///
/// # Examples
///
/// ```
/// use crypthix_types::cbor::{Document, Limits};
///
/// // {-1: 7, -2: h'0102'}
/// let bytes = [0xa2, 0x20, 0x07, 0x21, 0x42, 0x01, 0x02];
/// let document = Document::parse(&bytes, &Limits::FORMAT_0)?;
/// let mut map = document.root().map()?;
/// assert_eq!(map.required(-1)?.uint()?, 7);
/// assert_eq!(map.required(-2)?.bytes()?, [1, 2]);
/// assert!(map.finish()?.is_empty());
/// # Ok::<(), crypthix_types::format_error::FormatError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Document<'a> {
    bytes: &'a [u8],
}

impl<'a> Document<'a> {
    /// Checks that `bytes` is exactly one CBOR item in the deterministic encoding of format 0.
    ///
    /// The checks are: shortest-form heads, definite lengths, map keys that are integers in
    /// i32 range and strictly increasing by their encoded bytes, no tags, floats or simple
    /// values other than `false`, `true` and `null`, valid UTF-8 text without control or
    /// bidirectional characters, the limits, and no trailing bytes.
    ///
    /// # Errors
    ///
    /// [`FormatError::NonCanonical`], [`FormatError::Schema`], [`FormatError::Limit`], [`FormatError::Truncated`] or [`FormatError::TrailingBytes`].
    pub fn parse(bytes: &'a [u8], limits: &Limits) -> Result<Self, FormatError> {
        validate::document(bytes, limits)?;
        Ok(Self { bytes })
    }

    /// A decoder positioned on the top-level item.
    #[must_use]
    pub const fn root(&self) -> Decoder<'a> {
        Decoder::new(self.bytes)
    }

    /// The document bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}
