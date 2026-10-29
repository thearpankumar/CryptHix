//! A structured CBOR value for structure-aware fuzzing.

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Unstructured};
use crypthix_types::cbor::{Decoder, Encoder, ItemKind};
use crypthix_types::format_error::FormatError;

/// Containers nested deeper than format 0 allows, so the depth limit is exercised too.
const MAX_MODEL_DEPTH: usize = 9;
/// Items per container, enough to reach every head width of the count.
const MAX_ITEMS: usize = 26;

/// A CBOR value of the format 0 subset, plus text that the format forbids.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CborModel {
    /// An unsigned integer.
    Unsigned(u64),
    /// The negative integer `-1 - n`, `n` at most 2^63 − 1.
    Negative(u64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A text string, possibly with characters FS-10 forbids.
    Text(String),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// An array.
    Array(Vec<CborModel>),
    /// A map with integer keys; the encoder sorts them.
    Map(BTreeMap<i32, CborModel>),
}

impl<'a> Arbitrary<'a> for CborModel {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Self::arbitrary_at(u, 0)
    }
}

impl CborModel {
    fn arbitrary_at(u: &mut Unstructured<'_>, depth: usize) -> arbitrary::Result<Self> {
        let kinds = if depth < MAX_MODEL_DEPTH { 7 } else { 5 };
        Ok(match u.int_in_range(0..=kinds)? {
            0 => CborModel::Unsigned(u.arbitrary()?),
            1 => CborModel::Negative(u.int_in_range(0..=i64::MAX.cast_unsigned())?),
            2 => {
                let len = u.int_in_range(0..=300)?;
                CborModel::Bytes(u.bytes(len.min(u.len()))?.to_vec())
            }
            3 => CborModel::Text(u.arbitrary()?),
            4 => CborModel::Bool(u.arbitrary()?),
            5 => CborModel::Null,
            6 => {
                let len = u.int_in_range(0..=MAX_ITEMS)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(Self::arbitrary_at(u, depth + 1)?);
                }
                CborModel::Array(items)
            }
            _ => {
                let len = u.int_in_range(0..=MAX_ITEMS)?;
                let mut entries = BTreeMap::new();
                for _ in 0..len {
                    entries.insert(u.arbitrary()?, Self::arbitrary_at(u, depth + 1)?);
                }
                CborModel::Map(entries)
            }
        })
    }

    /// Containers nested inside each other, counting this one.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            CborModel::Array(items) => 1 + items.iter().map(Self::depth).max().unwrap_or(0),
            CborModel::Map(entries) => 1 + entries.values().map(Self::depth).max().unwrap_or(0),
            _ => 0,
        }
    }

    /// Whether any text holds a character FS-10 forbids.
    #[must_use]
    pub fn has_forbidden_text(&self) -> bool {
        match self {
            CborModel::Text(text) => text.chars().any(|c| {
                c.is_control()
                    || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}')
                    || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
            }),
            CborModel::Array(items) => items.iter().any(Self::has_forbidden_text),
            CborModel::Map(entries) => entries.values().any(Self::has_forbidden_text),
            _ => false,
        }
    }

    /// Writes the value with the format 0 encoder.
    ///
    /// # Errors
    ///
    /// Whatever the encoder reports: forbidden text or too deep a nesting.
    pub fn encode(&self, out: &mut Encoder) -> Result<(), FormatError> {
        match self {
            CborModel::Unsigned(n) => out.uint(*n),
            CborModel::Negative(n) => {
                out.int(-1 - i64::try_from(*n).map_err(|_| FormatError::Schema)?);
            }
            CborModel::Bytes(bytes) => out.bytes(bytes),
            CborModel::Text(text) => out.text(text)?,
            CborModel::Bool(value) => out.bool(*value),
            CborModel::Null => out.null(),
            CborModel::Array(items) => {
                out.array(|out| items.iter().try_for_each(|item| item.encode(out)))?;
            }
            CborModel::Map(entries) => out.map(|map| {
                entries
                    .iter()
                    .try_for_each(|(key, value)| map.entry(*key, |out| value.encode(out)))
            })?,
        }
        Ok(())
    }

    /// Reads a value back with the typed reads.
    ///
    /// # Errors
    ///
    /// Any typed-read error.
    pub fn decode(item: Decoder<'_>) -> Result<Self, FormatError> {
        Ok(match item.kind()? {
            ItemKind::Unsigned => CborModel::Unsigned(item.uint()?),
            ItemKind::Negative => {
                let n = -1 - item.int()?;
                CborModel::Negative(u64::try_from(n).map_err(|_| FormatError::Schema)?)
            }
            ItemKind::Bytes => CborModel::Bytes(item.bytes()?.to_vec()),
            ItemKind::Text => CborModel::Text(item.text()?.to_owned()),
            ItemKind::Bool => CborModel::Bool(item.bool()?),
            ItemKind::Null => CborModel::Null,
            ItemKind::Array => CborModel::Array(
                item.array()?
                    .map(|item| Self::decode(item?))
                    .collect::<Result<_, _>>()?,
            ),
            ItemKind::Map => CborModel::Map(
                item.map()?
                    .iter()
                    .map(|(key, value)| Ok((key, Self::decode(value)?)))
                    .collect::<Result<_, FormatError>>()?,
            ),
            _ => return Err(FormatError::Schema),
        })
    }
}
