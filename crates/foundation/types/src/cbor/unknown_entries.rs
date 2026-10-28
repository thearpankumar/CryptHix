//! Unknown non-critical map entries (FS-20).

use crate::cbor::RawItem;

/// Highest non-critical key that a writer copies unchanged when it rewrites a structure
/// without understanding the key (FS-20).
pub const SAFE_TO_COPY_MAX: i32 = 4095;

/// The non-critical entries of a map that its schema does not know.
///
/// They are ignored for meaning but stay authenticated, and are kept as raw bytes so the map can
/// be re-encoded exactly (FS-08, FS-20).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct UnknownEntries<'a> {
    entries: Vec<(i32, RawItem<'a>)>,
}

impl<'a> UnknownEntries<'a> {
    pub(crate) fn new(entries: Vec<(i32, RawItem<'a>)>) -> Self {
        Self { entries }
    }

    /// The entries, in ascending key order.
    pub fn iter(&self) -> impl Iterator<Item = (i32, RawItem<'a>)> + '_ {
        self.entries.iter().copied()
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Keeps only the safe-to-copy entries (keys 0 to 4095), for a writer that rewrites the
    /// structure (FS-20).
    pub fn retain_safe_to_copy(&mut self) {
        self.entries
            .retain(|(key, _)| (0..=SAFE_TO_COPY_MAX).contains(key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_only_safe_to_copy_keys() {
        let raw = RawItem::new(&[0x00]);
        let mut entries = UnknownEntries::new(vec![(1, raw), (4095, raw), (4096, raw)]);
        entries.retain_safe_to_copy();
        let keys: Vec<i32> = entries.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, [1, 4095]);
    }
}
