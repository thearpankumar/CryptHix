//! `MAC(k, x)`: keyed BLAKE3-256 under a single-purpose key (FS-26), and the keyed XOF of the
//! gear table (FS-52).

use zeroize::Zeroize;

use crate::hash::Hash32;
use crate::key::sealed;
use crate::key::{MacKey, XofKey};

/// An incremental `MAC`, for input that arrives in parts. Its key state is wiped on drop.
#[must_use]
pub struct Mac(blake3::Hasher);

impl Mac {
    /// Starts a MAC under `key`.
    pub fn new(key: &MacKey) -> Self {
        Self::keyed(sealed::material(key))
    }

    /// Starts a MAC under raw key bytes, for this crate's single-purpose keys of other types.
    pub(crate) fn keyed(key: &[u8; 32]) -> Self {
        Self(blake3::Hasher::new_keyed(key))
    }

    /// Appends input.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    /// The 32-byte MAC of everything appended so far.
    #[must_use]
    pub fn finalize(&self) -> Hash32 {
        Hash32::from_output(*self.0.finalize().as_bytes())
    }
}

impl Drop for Mac {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mac(..)")
    }
}

/// `MAC(key, data)`.
#[must_use]
pub fn mac(key: &MacKey, data: &[u8]) -> Hash32 {
    let mut mac = Mac::new(key);
    mac.update(data);
    mac.finalize()
}

/// Fills `out` with the keyed BLAKE3 XOF under `key` over the empty input; the gear table is its
/// first 2,048 bytes (FS-52). The hasher and the output reader, which both hold key-derived
/// state, are wiped afterwards.
pub fn xof(key: &XofKey, out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_keyed(sealed::material(key));
    let mut reader = hasher.finalize_xof();
    reader.fill(out);
    reader.zeroize();
    hasher.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_keyed_blake3() {
        let key: MacKey = sealed::from_material([5; 32]);
        let expected = *blake3::keyed_hash(&[5; 32], b"data").as_bytes();
        assert_eq!(mac(&key, b"data").as_bytes(), &expected);
    }

    #[test]
    fn xof_extends_the_keyed_hash() {
        let key: XofKey = sealed::from_material([5; 32]);
        let mut out = [0u8; 2048];
        xof(&key, &mut out);
        assert_eq!(&out[..32], blake3::keyed_hash(&[5; 32], b"").as_bytes());
    }
}
