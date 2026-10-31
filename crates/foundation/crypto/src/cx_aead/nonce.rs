//! Hedged and synthetic nonces (FS-29).

use crate::cx_aead::NONCE_LEN;
use crate::hash::Hash32;
use crate::kdf;
use crate::key::sealed;
use crate::key::{SealKey, ShardNonceKey};
use crate::label::KdfLabel;
use crate::mac::Mac;

/// The hedged nonce `MAC(K_n, rand ‖ a ‖ pt)[..24]`, where
/// `K_n = HKDF-Expand(K, u8 len ‖ "crypthix/v0/kdf/cx-nonce", 32)` and `a = H(hash/cx-aad, AAD)`.
#[cfg_attr(
    not(feature = "vectors"),
    expect(unreachable_pub, reason = "public only with `vectors`, for TV-05")
)]
#[must_use]
pub fn hedged_nonce(key: &SealKey, a: &Hash32, plaintext: &[u8], rand: &[u8; 32]) -> [u8; 24] {
    let nonce_key = kdf::expand(sealed::material(key), KdfLabel::CxNonce, &[]);
    let mut mac = Mac::keyed(&nonce_key);
    mac.update(rand).update(a.as_bytes()).update(plaintext);
    mac.finalize().prefix::<NONCE_LEN>()
}

/// The synthetic nonce `MAC(K_shn, a ‖ pt)[..24]`.
#[cfg_attr(
    not(feature = "vectors"),
    expect(unreachable_pub, reason = "public only with `vectors`, for TV-05")
)]
#[must_use]
pub fn synthetic_nonce(nonce_key: &ShardNonceKey, a: &Hash32, plaintext: &[u8]) -> [u8; 24] {
    let mut mac = Mac::keyed(sealed::material(nonce_key));
    mac.update(a.as_bytes()).update(plaintext);
    mac.finalize().prefix::<NONCE_LEN>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(byte: u8) -> Hash32 {
        Hash32::from_output([byte; 32])
    }

    #[test]
    fn hedged_depends_on_every_input() {
        let key: SealKey = sealed::from_material([1; 32]);
        let other_key: SealKey = sealed::from_material([2; 32]);
        let base = hedged_nonce(&key, &a(1), b"pt", &[0; 32]);
        assert_eq!(base, hedged_nonce(&key, &a(1), b"pt", &[0; 32]));
        assert_ne!(
            base,
            hedged_nonce(&other_key, &a(1), b"pt", &[0; 32]),
            "key ignored"
        );
        assert_ne!(
            base,
            hedged_nonce(&key, &a(2), b"pt", &[0; 32]),
            "AAD ignored"
        );
        assert_ne!(
            base,
            hedged_nonce(&key, &a(1), b"pT", &[0; 32]),
            "plaintext ignored"
        );
        assert_ne!(
            base,
            hedged_nonce(&key, &a(1), b"pt", &[1; 32]),
            "randomness ignored"
        );
    }

    #[test]
    fn synthetic_is_deterministic_and_content_bound() {
        let key: ShardNonceKey = sealed::from_material([1; 32]);
        let base = synthetic_nonce(&key, &a(1), b"header");
        assert_eq!(base, synthetic_nonce(&key, &a(1), b"header"));
        assert_ne!(
            base,
            synthetic_nonce(&key, &a(1), b"Header"),
            "header ignored"
        );
        assert_ne!(base, synthetic_nonce(&key, &a(2), b"header"), "AAD ignored");
    }
}
