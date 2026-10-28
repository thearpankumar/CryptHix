//! Schema-level reads of a CBOR map (FS-09, FS-20, FS-22).

use crate::cbor::{Decoder, UnknownEntries};
use crate::format_error::FormatError;
use crate::registry::grease;

/// The entries of a CBOR map, read by key.
///
/// Read the keys the schema knows with [`required`](Self::required) and
/// [`optional`](Self::optional), then call [`finish`](Self::finish), which rejects an unread
/// critical (negative) key and returns the unread non-critical ones.
#[must_use = "an unknown critical key is only rejected by MapReader::finish"]
#[derive(Clone, Debug)]
pub struct MapReader<'a> {
    /// Sorted by key, so lookups can binary-search.
    entries: Vec<Entry<'a>>,
}

#[derive(Clone, Debug)]
struct Entry<'a> {
    key: i32,
    value: Decoder<'a>,
    read: bool,
}

impl<'a> MapReader<'a> {
    pub(crate) fn new(entries: Vec<(i32, Decoder<'a>)>) -> Self {
        let mut entries: Vec<Entry<'a>> = entries
            .into_iter()
            .map(|(key, value)| Entry {
                key,
                value,
                read: false,
            })
            .collect();
        entries.sort_unstable_by_key(|entry| entry.key);
        Self { entries }
    }

    /// The value of a required key.
    ///
    /// # Errors
    ///
    /// [`FormatError::Schema`] if the key is missing.
    pub fn required(&mut self, key: i32) -> Result<Decoder<'a>, FormatError> {
        self.optional(key)?.ok_or(FormatError::Schema)
    }

    /// The value of an optional key, or `None` if it is left out.
    ///
    /// # Errors
    ///
    /// None today; the `Result` keeps the signature of [`required`](Self::required).
    pub fn optional(&mut self, key: i32) -> Result<Option<Decoder<'a>>, FormatError> {
        let Ok(index) = self.entries.binary_search_by_key(&key, |entry| entry.key) else {
            return Ok(None);
        };
        let entry = &mut self.entries[index];
        entry.read = true;
        Ok(Some(entry.value))
    }

    /// Every entry in ascending key order, without marking any as read.
    pub fn iter(&self) -> impl Iterator<Item = (i32, Decoder<'a>)> + '_ {
        self.entries.iter().map(|entry| (entry.key, entry.value))
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Ends the read and returns the unknown non-critical entries.
    ///
    /// GREASE keys of either sign are never critical (FS-22). They are kept among the unknown
    /// entries with the other unread keys, so the map re-encodes to exactly its input.
    ///
    /// # Errors
    ///
    /// [`FormatError::UnknownCritical`] if a negative key was not read (FS-09, FS-20).
    pub fn finish(self) -> Result<UnknownEntries<'a>, FormatError> {
        let mut unknown = Vec::new();
        for entry in self.entries {
            if entry.read {
                continue;
            }
            if entry.key < 0 && !grease::is_grease_value(i64::from(entry.key)) {
                return Err(FormatError::UnknownCritical);
            }
            unknown.push((entry.key, entry.value.raw()));
        }
        Ok(UnknownEntries::new(unknown))
    }
}

#[cfg(test)]
mod tests {
    use crate::cbor::{Document, Limits};
    use crate::format_error::FormatError;

    fn finish(bytes: &[u8], known: &[i32]) -> Result<Vec<(i32, Vec<u8>)>, FormatError> {
        let document = Document::parse(bytes, &Limits::FORMAT_0)?;
        let mut map = document.root().map()?;
        for key in known {
            map.required(*key)?;
        }
        let unknown = map.finish()?;
        Ok(unknown
            .iter()
            .map(|(key, raw)| (key, raw.as_bytes().to_vec()))
            .collect())
    }

    #[test]
    fn required_and_optional() {
        let document = Document::parse(&[0xa2, 0x01, 0x02, 0x20, 0x03], &Limits::FORMAT_0)
            .expect("valid document");
        let mut map = document.root().map().expect("map");
        assert_eq!(map.len(), 2);
        assert_eq!(map.required(-1).and_then(|value| value.uint()), Ok(3));
        assert_eq!(map.optional(5).map(|value| value.is_none()), Ok(true));
        assert_eq!(map.required(5).map(|_| ()), Err(FormatError::Schema));
    }

    #[test]
    fn unknown_critical_key_is_rejected() {
        // {1: 0, -1: 0, -2: 0} with only -1 known.
        assert_eq!(
            finish(&[0xa3, 0x01, 0x00, 0x20, 0x00, 0x21, 0x00], &[-1]),
            Err(FormatError::UnknownCritical)
        );
    }

    #[test]
    fn unknown_non_critical_key_is_kept_raw() {
        // {1: h'aa', -1: 0} with only -1 known.
        assert_eq!(
            finish(&[0xa2, 0x01, 0x41, 0xaa, 0x20, 0x00], &[-1]),
            Ok(vec![(1, vec![0x41, 0xaa])])
        );
    }

    #[test]
    fn grease_keys_are_never_critical_and_are_kept() {
        // {0x0a0a: 0, -0x0a0a: 0}: 0x19 0x0a 0x0a and 0x39 0x0a 0x09.
        assert_eq!(
            finish(&[0xa2, 0x19, 0x0a, 0x0a, 0x00, 0x39, 0x0a, 0x09, 0x00], &[]),
            Ok(vec![(-0x0a0a, vec![0x00]), (0x0a0a, vec![0x00])])
        );
    }

    #[test]
    fn unknown_entries_re_encode_exactly() {
        use crate::cbor::Encoder;

        // {1: 0, 0x0a0a: h'aa', -1: 0} with only -1 known.
        let bytes = [0xa3, 0x01, 0x00, 0x19, 0x0a, 0x0a, 0x41, 0xaa, 0x20, 0x00];
        let document = Document::parse(&bytes, &Limits::FORMAT_0).expect("valid document");
        let mut map = document.root().map().expect("map");
        let known = map.required(-1).expect("present").uint().expect("integer");
        let unknown = map.finish().expect("no unknown critical key");
        let mut encoder = Encoder::new();
        encoder
            .map(|writer| {
                writer.entry(-1, |value| {
                    value.uint(known);
                    Ok(())
                })?;
                writer.unknown_entries(&unknown);
                Ok(())
            })
            .expect("encodes");
        assert_eq!(encoder.finish(&Limits::FORMAT_0).as_deref(), Ok(&bytes[..]));
    }
}
