//! Map entries collected for the encoder.

use crate::cbor::head;
use crate::cbor::{Encoder, RawItem, UnknownEntries};
use crate::format_error::FormatError;

/// Collects the entries of a CBOR map; the encoder sorts them by encoded key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MapWriter {
    /// Encoded key and encoded value of each entry.
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// An empty encoder at the map's nesting level, used to start each value.
    level: Encoder,
}

impl MapWriter {
    pub(crate) fn new(level: Encoder) -> Self {
        Self {
            entries: Vec::new(),
            level,
        }
    }

    /// Adds an entry whose value `write` encodes as exactly one item.
    ///
    /// # Errors
    ///
    /// [`FormatError::NonCanonical`] if `write` wrote no item or more than one, or any error it
    /// returns.
    pub fn entry<F>(&mut self, key: i32, write: F) -> Result<(), FormatError>
    where
        F: FnOnce(&mut Encoder) -> Result<(), FormatError>,
    {
        let mut value = self.level.clone();
        write(&mut value)?;
        if value.items() != 1 {
            return Err(FormatError::NonCanonical);
        }
        self.push(key, value.as_bytes().to_vec());
        Ok(())
    }

    /// Adds an entry whose value is a raw item, such as an unknown entry carried unchanged.
    pub fn raw_entry(&mut self, key: i32, value: RawItem<'_>) {
        self.push(key, value.as_bytes().to_vec());
    }

    /// Adds every unknown entry unchanged (FS-20).
    pub fn unknown_entries(&mut self, unknown: &UnknownEntries<'_>) {
        for (key, value) in unknown.iter() {
            self.raw_entry(key, value);
        }
    }

    fn push(&mut self, key: i32, value: Vec<u8>) {
        let mut encoded_key = Encoder::new();
        encoded_key.int(i64::from(key));
        self.entries.push((encoded_key.as_bytes().to_vec(), value));
    }

    /// Writes the map, sorted by encoded key, to `out`.
    pub(crate) fn write_to(mut self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        self.entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        if self.entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(FormatError::NonCanonical);
        }
        head::write(out, head::MAP, self.entries.len() as u64);
        for (key, value) in &self.entries {
            out.extend_from_slice(key);
            out.extend_from_slice(value);
        }
        Ok(())
    }
}
