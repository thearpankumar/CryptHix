//! The seeded stream of the vector generator (FS-94), behind the `test-rng` feature.
//!
//! Release builds never enable the feature (FS-01); `cargo xtask check-features` fails if the
//! main workspace does.

use chacha20::ChaCha20Rng;
use chacha20::rand_core::{Rng, SeedableRng};

/// A deterministic byte stream: `ChaCha20` seeded with `BLAKE3-keyed(seed, label)`, so every test
/// of a vector set draws from its own labelled stream.
///
/// It offers only [`fill_bytes`](Self::fill_bytes), never ranges or distributions that may change
/// between `rand` releases (FS-94).
///
/// ```
/// use crypthix_crypto::test_rng::Stream;
///
/// let seed = [1u8; 32];
/// let mut first = [0u8; 8];
/// let mut again = [0u8; 8];
/// let mut other = [0u8; 8];
/// Stream::new(&seed, "tc 1").fill_bytes(&mut first);
/// Stream::new(&seed, "tc 1").fill_bytes(&mut again);
/// Stream::new(&seed, "tc 2").fill_bytes(&mut other);
/// assert_eq!(first, again);
/// assert_ne!(first, other);
/// ```
#[derive(Debug)]
pub struct Stream(ChaCha20Rng);

impl Stream {
    /// The stream named `label` under the set's `seed`.
    #[must_use]
    pub fn new(seed: &[u8; 32], label: &str) -> Self {
        let stream_seed = blake3::keyed_hash(seed, label.as_bytes());
        Self(ChaCha20Rng::from_seed(*stream_seed.as_bytes()))
    }

    /// Fills `out` with the next bytes of the stream.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        self.0.fill_bytes(out);
    }

    /// The next `N` bytes of the stream.
    #[must_use]
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill_bytes(&mut out);
        out
    }
}
