//! The incremental and one-shot forms of `H`.

use crate::hash::Hash32;
use crate::label::HashLabel;

/// An incremental `H(label, x)` for input that arrives in parts, such as a whole file.
///
/// ```
/// use crypthix_crypto::hash::{self, Hasher};
/// use crypthix_crypto::label::HashLabel;
///
/// let mut hasher = Hasher::new(HashLabel::File);
/// hasher.update(b"hello ");
/// hasher.update(b"world");
/// assert_eq!(hasher.finalize(), hash::hash(HashLabel::File, b"hello world"));
/// ```
#[must_use]
#[derive(Clone, Debug)]
pub struct Hasher(blake3::Hasher);

impl Hasher {
    /// Starts `H` under `label`: BLAKE3 over `u8 len(label) ‖ label ‖ x` (section 7.1).
    pub fn new(label: HashLabel) -> Self {
        let mut inner = blake3::Hasher::new();
        label.write_prefix(&mut inner);
        Self(inner)
    }

    /// Appends input.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    /// The 32-byte hash of everything appended so far.
    #[must_use]
    pub fn finalize(&self) -> Hash32 {
        Hash32::from_output(*self.0.finalize().as_bytes())
    }
}

/// `H(label, data)`.
#[must_use]
pub fn hash(label: HashLabel, data: &[u8]) -> Hash32 {
    let mut hasher = Hasher::new(label);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_blake3_of_the_prefixed_input() {
        let mut input = vec![23u8];
        input.extend_from_slice(b"crypthix/v0/hash/key-id");
        input.extend_from_slice(b"public key");
        assert_eq!(input[0] as usize, b"crypthix/v0/hash/key-id".len());
        let expected = *blake3::hash(&input).as_bytes();
        assert_eq!(hash(HashLabel::KeyId, b"public key").as_bytes(), &expected);
    }

    #[test]
    fn labels_separate_domains() {
        assert_ne!(hash(HashLabel::File, b"x"), hash(HashLabel::Pack, b"x"));
    }
}
