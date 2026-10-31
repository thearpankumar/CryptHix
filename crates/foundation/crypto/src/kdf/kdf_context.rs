//! The fixed-width context of a KDF call (FS-12, FS-38).

/// A KDF context: fixed-width fields written one after the other, with no lengths (FS-12).
///
/// Only fixed-width fields can be added, so for one label, whose context has one fixed list of
/// fields (FS-38), two different contexts never encode to the same bytes.
#[must_use]
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct KdfContext(Vec<u8>);

impl KdfContext {
    /// An empty context.
    pub fn new() -> Self {
        Self(Vec::with_capacity(64))
    }

    /// Appends a fixed-width field, such as an ID.
    pub fn field<const N: usize>(mut self, bytes: &[u8; N]) -> Self {
        self.0.extend_from_slice(bytes);
        self
    }

    /// Appends a `u32be`, such as an epoch or keyring generation.
    pub fn u32be(self, value: u32) -> Self {
        self.field(&value.to_be_bytes())
    }

    /// Appends a `u64be`, such as a root sequence number.
    pub fn u64be(self, value: u64) -> Self {
        self.field(&value.to_be_bytes())
    }

    /// Wraps context bytes built elsewhere, for the test-vector runners only.
    #[cfg(feature = "vectors")]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The context bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_concatenated() {
        let context = KdfContext::new().field(&[1, 2]).u32be(3).u64be(4);
        assert_eq!(
            context.as_bytes(),
            &[1, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4]
        );
    }
}
