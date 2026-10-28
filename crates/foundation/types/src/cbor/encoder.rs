//! The deterministic CBOR encoder (FS-08).

use crate::cbor::head;
use crate::cbor::validate;
use crate::cbor::{Limits, MapWriter, RawItem};
use crate::format_error::FormatError;

/// Writes CBOR in the deterministic encoding of format 0: shortest-form heads, definite lengths
/// and map keys sorted by their encoded bytes.
///
/// # Examples
///
/// ```
/// use crypthix_types::cbor::{Encoder, Limits};
///
/// let mut encoder = Encoder::new();
/// encoder.map(|map| {
///     map.entry(24, |value| {
///         value.bool(true);
///         Ok(())
///     })?;
///     map.entry(-1, |value| {
///         value.uint(7);
///         Ok(())
///     })
/// })?;
/// // Key 24 (0x18 0x18) sorts before key -1 (0x20).
/// assert_eq!(encoder.finish(&Limits::FORMAT_0)?, [0xa2, 0x18, 0x18, 0xf5, 0x20, 0x07]);
/// # Ok::<(), crypthix_types::format_error::FormatError>(())
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Encoder {
    out: Vec<u8>,
    /// Items written at this level, so containers know their length without re-reading.
    items: u64,
    /// Containers this encoder is nested in.
    depth: usize,
}

impl Encoder {
    /// An empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            out: Vec::new(),
            items: 0,
            depth: 0,
        }
    }

    /// An encoder for the items inside a container at this level.
    fn nested(&self) -> Result<Self, FormatError> {
        let depth = self.depth + 1;
        if depth > Limits::FORMAT_0.max_depth() {
            return Err(FormatError::Limit);
        }
        Ok(Self {
            out: Vec::new(),
            items: 0,
            depth,
        })
    }

    /// The number of items written at this level.
    pub(crate) const fn items(&self) -> u64 {
        self.items
    }

    /// The bytes written so far.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.out
    }

    /// The finished document, checked against `limits` exactly as a reader would check it, so
    /// a writer never produces a file that readers reject.
    ///
    /// # Errors
    ///
    /// Any error of [`Document::parse`](crate::cbor::Document::parse), for example
    /// [`FormatError::Limit`] for a document over the limits.
    pub fn finish(self, limits: &Limits) -> Result<Vec<u8>, FormatError> {
        validate::document(&self.out, limits)?;
        Ok(self.out)
    }

    /// Writes an unsigned integer.
    pub fn uint(&mut self, value: u64) {
        head::write(&mut self.out, head::UNSIGNED, value);
        self.items += 1;
    }

    /// Writes a signed integer.
    pub fn int(&mut self, value: i64) {
        if value >= 0 {
            head::write(&mut self.out, head::UNSIGNED, value.unsigned_abs());
        } else {
            // -1 - argument == value, so argument == |value| - 1.
            head::write(&mut self.out, head::NEGATIVE, value.unsigned_abs() - 1);
        }
        self.items += 1;
    }

    /// Writes a byte string.
    pub fn bytes(&mut self, value: &[u8]) {
        head::write(&mut self.out, head::BYTES, value.len() as u64);
        self.out.extend_from_slice(value);
        self.items += 1;
    }

    /// Writes a text string.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the text contains a control or bidirectional formatting
    /// character (FS-10).
    pub fn text(&mut self, value: &str) -> Result<(), FormatError> {
        validate::check_text(value)?;
        head::write(&mut self.out, head::TEXT, value.len() as u64);
        self.out.extend_from_slice(value.as_bytes());
        self.items += 1;
        Ok(())
    }

    /// Writes `true` or `false`.
    pub fn bool(&mut self, value: bool) {
        self.out.push(if value { 0xf5 } else { 0xf4 });
        self.items += 1;
    }

    /// Writes `null`. Use only where a schema says `/ null`; optional fields are left out.
    pub fn null(&mut self) {
        self.out.push(0xf6);
        self.items += 1;
    }

    /// Writes a raw item unchanged.
    pub fn raw(&mut self, item: RawItem<'_>) {
        self.out.extend_from_slice(item.as_bytes());
        self.items += 1;
    }

    /// Writes an array whose items `write` encodes; the length is counted from them.
    ///
    /// # Errors
    ///
    /// [`FormatError::Limit`] if arrays and maps nest deeper than format 0 allows, or any
    /// error returned by `write`.
    pub fn array<F>(&mut self, write: F) -> Result<(), FormatError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), FormatError>,
    {
        let mut items = self.nested()?;
        write(&mut items)?;
        head::write(&mut self.out, head::ARRAY, items.items);
        self.out.extend_from_slice(&items.out);
        self.items += 1;
        Ok(())
    }

    /// Writes a map whose entries `write` adds, sorted by encoded key.
    ///
    /// # Errors
    ///
    /// [`FormatError::NonCanonical`] for a duplicate key, [`FormatError::Limit`] if arrays and
    /// maps nest deeper than format 0 allows, or any error returned by `write`.
    pub fn map<F>(&mut self, write: F) -> Result<(), FormatError>
    where
        F: FnOnce(&mut MapWriter) -> Result<(), FormatError>,
    {
        let mut map = MapWriter::new(self.nested()?);
        write(&mut map)?;
        map.write_to(&mut self.out)?;
        self.items += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cbor::{Document, Limits};

    fn encode(write: impl FnOnce(&mut Encoder)) -> Vec<u8> {
        let mut encoder = Encoder::new();
        write(&mut encoder);
        encoder.as_bytes().to_vec()
    }

    #[test]
    fn integers() {
        assert_eq!(encode(|e| e.int(0)), [0x00]);
        assert_eq!(encode(|e| e.int(-1)), [0x20]);
        assert_eq!(encode(|e| e.int(-25)), [0x38, 0x18]);
        assert_eq!(
            encode(|e| e.int(i64::MIN)),
            [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            encode(|e| e.uint(u64::MAX)),
            [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn strings_and_simple_values() {
        assert_eq!(encode(|e| e.bytes(&[1, 2])), [0x42, 1, 2]);
        assert_eq!(
            encode(|e| e.text("hi").expect("plain text")),
            [0x62, b'h', b'i']
        );
        assert_eq!(Encoder::new().text("a\u{202E}b"), Err(FormatError::Schema));
        assert_eq!(encode(|e| e.bool(false)), [0xf4]);
        assert_eq!(encode(Encoder::null), [0xf6]);
    }

    #[test]
    fn arrays_count_their_items() {
        let bytes = encode(|e| {
            e.array(|items| {
                items.uint(1);
                items.array(|inner| {
                    inner.uint(2);
                    Ok(())
                })
            })
            .expect("encodes");
        });
        assert_eq!(bytes, [0x82, 0x01, 0x81, 0x02]);
    }

    fn uint_entry(map: &mut MapWriter, key: i32, value: u64) -> Result<(), FormatError> {
        map.entry(key, |encoder| {
            encoder.uint(value);
            Ok(())
        })
    }

    #[test]
    fn maps_sort_by_encoded_key() {
        let bytes = encode(|e| {
            e.map(|map| {
                uint_entry(map, -1, 1)?;
                uint_entry(map, 24, 2)?;
                uint_entry(map, 0, 3)
            })
            .expect("encodes");
        });
        assert_eq!(bytes, [0xa3, 0x00, 0x03, 0x18, 0x18, 0x02, 0x20, 0x01]);
        assert_eq!(
            Document::parse(&bytes, &Limits::FORMAT_0).map(|_| ()),
            Ok(())
        );
    }

    #[test]
    fn nesting_is_bounded_while_encoding() {
        fn nest(encoder: &mut Encoder, levels: usize) -> Result<(), FormatError> {
            if levels == 0 {
                encoder.uint(0);
                return Ok(());
            }
            encoder.array(|inner| nest(inner, levels - 1))
        }
        assert_eq!(nest(&mut Encoder::new(), 8), Ok(()));
        assert_eq!(nest(&mut Encoder::new(), 9), Err(FormatError::Limit));
    }

    #[test]
    fn finish_checks_the_reader_limits() {
        let mut encoder = Encoder::new();
        encoder.bytes(&[0; 8]);
        let tight = Limits::FORMAT_0.with_max_string_len(4);
        assert_eq!(encoder.clone().finish(&tight), Err(FormatError::Limit));
        assert_eq!(
            encoder.finish(&Limits::FORMAT_0).map(|bytes| bytes.len()),
            Ok(9)
        );
    }

    #[test]
    fn duplicate_keys_are_refused() {
        let result = Encoder::new().map(|map| {
            uint_entry(map, 1, 1)?;
            uint_entry(map, 1, 2)
        });
        assert_eq!(result, Err(FormatError::NonCanonical));
    }

    #[test]
    fn a_map_value_must_be_one_item() {
        let none = Encoder::new().map(|map| map.entry(1, |_| Ok(())));
        assert_eq!(none, Err(FormatError::NonCanonical));
        let two = Encoder::new().map(|map| {
            map.entry(1, |value| {
                value.uint(1);
                value.uint(2);
                Ok(())
            })
        });
        assert_eq!(two, Err(FormatError::NonCanonical));
    }
}
