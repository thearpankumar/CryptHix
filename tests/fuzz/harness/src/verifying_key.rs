//! Ed25519 public keys and signatures on hostile input, checked against a second reading of
//! FS-14 built directly on curve25519-dalek and ed25519-dalek.

use crypthix_crypto::sign::{Signature, VerifyingKey};
use curve25519_dalek::edwards::CompressedEdwardsY;

/// Whether FS-14 accepts `bytes` as a public key: a point, canonically encoded, in the
/// prime-order subgroup (so neither small nor mixed order).
fn strict_key(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes)
        .decompress()
        .is_some_and(|point| {
            point.compress().to_bytes() == *bytes
                && point.is_torsion_free()
                && !point.is_small_order()
        })
}

/// Reads `data` as `public key[32] ‖ signature[64] ‖ message`.
///
/// # Panics
///
/// If the crate accepts a key FS-14 rejects or rejects one it accepts, an accepted key changes
/// its bytes, or a signature verifies that `verify_strict` alone would reject.
pub fn verifying_key(data: &[u8]) {
    let Some((key, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let parsed = VerifyingKey::from_bytes(key);
    assert_eq!(
        parsed.is_ok(),
        strict_key(key),
        "key {key:02x?}: FS-14 disagrees"
    );
    let Ok(public) = parsed else {
        return;
    };
    assert_eq!(public.as_bytes(), key, "an accepted key keeps its bytes");
    let Some((signature, message)) = rest.split_first_chunk::<64>() else {
        return;
    };
    if public
        .verify_raw(message, &Signature::from_bytes(*signature))
        .is_ok()
    {
        let reference = ed25519_dalek::VerifyingKey::from_bytes(key).expect("a strict key decodes");
        let signature = ed25519_dalek::Signature::from_bytes(signature);
        assert!(
            reference.verify_strict(message, &signature).is_ok(),
            "accepted a signature that verify_strict rejects"
        );
    }
}
