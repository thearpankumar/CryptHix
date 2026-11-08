//! The incremental and one-shot forms of `H`.

use std::fmt;

use zeroize::Zeroize;

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
///
/// Its state is derived from the input, which may be plaintext, so it is wiped on drop and does
/// not print.
#[must_use]
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

impl Drop for Hasher {
    fn drop(&mut self) {
        self.0.zeroize();
        // Test seam: the state is gone once the drop returns, so tests see it here, after the
        // wipe.
        #[cfg(test)]
        tests::WIPED_ON_DROP.set(Some(tests::is_wiped(&self.0)));
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hasher(..)")
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
    use std::cell::Cell;

    use super::*;

    std::thread_local! {
        /// Set by each `Hasher` this thread drops, after its wipe: whether its state was then
        /// all zero. `None` until a hasher is dropped.
        pub(super) static WIPED_ON_DROP: Cell<Option<bool>> = const { Cell::new(None) };
    }

    /// Whether `state` is a wiped BLAKE3 state, seen through its public methods: no input is
    /// counted, and it finalizes to what a wiped fresh state does. Any key, chaining value,
    /// buffered block or stacked chaining value left in it changes that output.
    pub(super) fn is_wiped(state: &blake3::Hasher) -> bool {
        let mut wiped = blake3::Hasher::new();
        wiped.zeroize();
        state.count() == 0 && state.finalize() == wiped.finalize()
    }

    /// A hasher fed more than one chunk (so it holds a chaining value on its stack and a
    /// partial block) is all zero by the time its drop returns.
    #[test]
    fn a_dropped_hasher_is_wiped() {
        let mut hasher = Hasher::new(HashLabel::File);
        hasher.update(&[0x5a; 3000]);
        assert!(!is_wiped(&hasher.0), "the check sees a live state");
        WIPED_ON_DROP.set(None);
        drop(hasher);
        assert_eq!(WIPED_ON_DROP.take(), Some(true));
    }

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
