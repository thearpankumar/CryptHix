//! Typed reads of one item in a validated document.

use crate::cbor::head;
use std::iter::FusedIterator;

use crate::cbor::{Document, Limits, MapReader, RawItem};
use crate::format_error::FormatError;

/// The kind of a CBOR item, for generic readers.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ItemKind {
    /// An unsigned integer.
    Unsigned,
    /// A negative integer.
    Negative,
    /// A byte string.
    Bytes,
    /// A text string.
    Text,
    /// An array.
    Array,
    /// A map.
    Map,
    /// `true` or `false`.
    Bool,
    /// `null`.
    Null,
}

/// Typed reads of one item of a validated [`Document`].
///
/// A read of the wrong type is [`FormatError::Schema`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Decoder<'a> {
    item: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub(crate) const fn new(item: &'a [u8]) -> Self {
        Self { item }
    }

    fn head(&self) -> Result<head::Head, FormatError> {
        head::read(self.item, 0)
    }

    /// Payload of a byte or text string of the given major type.
    fn string(&self, major: u8) -> Result<&'a [u8], FormatError> {
        let head = self.head()?;
        if head.major != major {
            return Err(FormatError::Schema);
        }
        let len = usize::try_from(head.argument).map_err(|_| FormatError::Limit)?;
        self.item
            .get(head.len..)
            .and_then(|payload| payload.get(..len))
            .ok_or(FormatError::Truncated)
    }

    /// The kind of the item.
    ///
    /// # Errors
    ///
    /// None for an item of a validated document; the `Result` avoids a panic on a broken
    /// invariant.
    pub fn kind(&self) -> Result<ItemKind, FormatError> {
        let head = self.head()?;
        Ok(match (head.major, head.argument) {
            (head::UNSIGNED, _) => ItemKind::Unsigned,
            (head::NEGATIVE, _) => ItemKind::Negative,
            (head::BYTES, _) => ItemKind::Bytes,
            (head::TEXT, _) => ItemKind::Text,
            (head::ARRAY, _) => ItemKind::Array,
            (head::MAP, _) => ItemKind::Map,
            (head::SIMPLE, head::FALSE | head::TRUE) => ItemKind::Bool,
            (head::SIMPLE, head::NULL) => ItemKind::Null,
            _ => return Err(FormatError::NonCanonical),
        })
    }

    /// An unsigned integer.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the item is not an unsigned integer.
    pub fn uint(&self) -> Result<u64, FormatError> {
        let head = self.head()?;
        if head.major == head::UNSIGNED {
            Ok(head.argument)
        } else {
            Err(FormatError::Schema)
        }
    }

    /// A signed integer.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the item is not an integer or does not fit `i64`.
    pub fn int(&self) -> Result<i64, FormatError> {
        let head = self.head()?;
        let magnitude = i64::try_from(head.argument).map_err(|_| FormatError::Schema)?;
        match head.major {
            head::UNSIGNED => Ok(magnitude),
            head::NEGATIVE => Ok(-1 - magnitude),
            _ => Err(FormatError::Schema),
        }
    }

    /// A byte string.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the item is not a byte string.
    pub fn bytes(&self) -> Result<&'a [u8], FormatError> {
        self.string(head::BYTES)
    }

    /// A byte string of exactly `N` bytes.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the item is not a byte string of that length.
    pub fn bytes_exact<const N: usize>(&self) -> Result<[u8; N], FormatError> {
        self.bytes()?.try_into().map_err(|_| FormatError::Schema)
    }

    /// A text string, already checked for UTF-8 and forbidden characters.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the item is not a text string.
    pub fn text(&self) -> Result<&'a str, FormatError> {
        std::str::from_utf8(self.string(head::TEXT)?).map_err(|_| FormatError::Schema)
    }

    /// A boolean.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the item is not `true` or `false`.
    pub fn bool(&self) -> Result<bool, FormatError> {
        match self.item {
            [0xf4] => Ok(false),
            [0xf5] => Ok(true),
            _ => Err(FormatError::Schema),
        }
    }

    /// Whether the item is `null`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.item == [0xf6]
    }

    /// `None` for `null`, otherwise the item. Use only where a schema says `/ null` (FS-10).
    #[must_use]
    pub fn nullable(&self) -> Option<Self> {
        if self.is_null() { None } else { Some(*self) }
    }

    /// The items of an array.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the item is not an array.
    pub fn array(&self) -> Result<ArrayIter<'a>, FormatError> {
        let head = self.head()?;
        if head.major != head::ARRAY {
            return Err(FormatError::Schema);
        }
        let rest = self.item.get(head.len..).ok_or(FormatError::Truncated)?;
        Ok(ArrayIter {
            rest,
            remaining: head.argument,
        })
    }

    /// The entries of a map. Call [`MapReader::finish`] after reading the known keys, or an
    /// unknown critical key goes unnoticed.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the item is not a map.
    #[must_use = "an unknown critical key is only rejected by MapReader::finish"]
    pub fn map(&self) -> Result<MapReader<'a>, FormatError> {
        let head = self.head()?;
        if head.major != head::MAP {
            return Err(FormatError::Schema);
        }
        let mut rest = self.item.get(head.len..).ok_or(FormatError::Truncated)?;
        let count = usize::try_from(head.argument).map_err(|_| FormatError::Limit)?;
        let mut entries = Vec::with_capacity(count.min(rest.len()));
        for _ in 0..count {
            let key;
            (key, rest) = split_item(rest)?;
            let value;
            (value, rest) = split_item(rest)?;
            let key = Decoder::new(key).int()?;
            let key = i32::try_from(key).map_err(|_| FormatError::Schema)?;
            entries.push((key, Decoder::new(value)));
        }
        Ok(MapReader::new(entries))
    }

    /// The item as raw bytes, for carrying it unchanged.
    #[must_use]
    pub const fn raw(&self) -> RawItem<'a> {
        RawItem::new(self.item)
    }

    /// A CBOR document carried inside a byte string, validated with its own budget (FS-08).
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the item is not a byte string, or any error of [`Document::parse`].
    pub fn nested_document(&self, limits: &Limits) -> Result<Document<'a>, FormatError> {
        Document::parse(self.bytes()?, limits)
    }
}

/// Splits the first item off `input`.
fn split_item(input: &[u8]) -> Result<(&[u8], &[u8]), FormatError> {
    let len = head::item_len(input)?;
    input.split_at_checked(len).ok_or(FormatError::Truncated)
}

/// The items of a CBOR array.
#[derive(Clone, Debug)]
pub struct ArrayIter<'a> {
    rest: &'a [u8],
    remaining: u64,
}

impl<'a> Iterator for ArrayIter<'a> {
    type Item = Result<Decoder<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        match split_item(self.rest) {
            Ok((item, rest)) => {
                self.rest = rest;
                Some(Ok(Decoder::new(item)))
            }
            Err(error) => {
                self.remaining = 0;
                Some(Err(error))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ArrayIter<'_> {}

impl FusedIterator for ArrayIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(bytes: &[u8]) -> Decoder<'_> {
        Document::parse(bytes, &Limits::FORMAT_0)
            .expect("valid document")
            .root()
    }

    #[test]
    fn scalars() {
        assert_eq!(root(&[0x18, 0x2a]).uint(), Ok(42));
        assert_eq!(root(&[0x38, 0x29]).int(), Ok(-42));
        assert_eq!(
            root(&[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).int(),
            Ok(i64::MIN)
        );
        assert_eq!(root(&[0x42, 1, 2]).bytes(), Ok(&[1u8, 2][..]));
        assert_eq!(root(&[0x42, 1, 2]).bytes_exact::<2>(), Ok([1, 2]));
        assert_eq!(root(&[0x62, b'h', b'i']).text(), Ok("hi"));
        assert_eq!(root(&[0xf5]).bool(), Ok(true));
        assert!(root(&[0xf6]).is_null(), "f6 is null");
        assert_eq!(root(&[0xf6]).nullable(), None);
    }

    #[test]
    fn wrong_types_are_schema_errors() {
        assert_eq!(root(&[0x20]).uint(), Err(FormatError::Schema));
        assert_eq!(
            root(&[0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0]).int(),
            Err(FormatError::Schema)
        );
        assert_eq!(root(&[0x61, b'a']).bytes(), Err(FormatError::Schema));
        assert_eq!(
            root(&[0x42, 1, 2]).bytes_exact::<3>(),
            Err(FormatError::Schema)
        );
        assert_eq!(root(&[0x40]).text(), Err(FormatError::Schema));
        assert_eq!(root(&[0xf6]).bool(), Err(FormatError::Schema));
        assert_eq!(root(&[0xa0]).array().map(|_| ()), Err(FormatError::Schema));
        assert_eq!(root(&[0x80]).map().map(|_| ()), Err(FormatError::Schema));
    }

    #[test]
    fn arrays() {
        let items: Result<Vec<u64>, FormatError> = root(&[0x83, 0x01, 0x02, 0x18, 0x18])
            .array()
            .expect("array")
            .map(|item| item.and_then(|item| item.uint()))
            .collect();
        assert_eq!(items, Ok(vec![1, 2, 24]));
        assert_eq!(root(&[0x82, 0x80, 0xa0]).array().expect("array").len(), 2);
    }

    #[test]
    fn nested_documents_are_validated() {
        // h'a10100' is {1: 0}; h'1805' is a non-shortest 5.
        let outer = root(&[0x43, 0xa1, 0x01, 0x00]);
        let inner = outer
            .nested_document(&Limits::FORMAT_0)
            .expect("canonical inner");
        assert_eq!(inner.root().map().expect("map").len(), 1);
        let outer = root(&[0x42, 0x18, 0x05]);
        assert_eq!(
            outer.nested_document(&Limits::FORMAT_0),
            Err(FormatError::NonCanonical)
        );
    }
}
