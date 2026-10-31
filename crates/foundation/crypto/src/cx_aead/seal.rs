//! Seal (FS-27).

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::aad::Aad;
use crate::cx_aead::nonce;
use crate::cx_aead::{
    COMMITMENT_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, NonceKind, OVERHEAD, SealError,
};
use crate::hash::{self, Hash32};
use crate::kdf;
use crate::key::sealed;
use crate::key::{KeyMaterial, SealKey};
use crate::label::{AadLabel, HashLabel, KdfLabel};
use crate::random::{self, RandomError};

/// Seals `plaintext` under `key` and `aad`, returning `nonce ‖ C ‖ ct ‖ tag`.
///
/// # Errors
///
/// - [`SealError::Random`] if a [`NonceKind::Hedged`] nonce cannot get its randomness from the
///   kernel.
/// - [`SealError::TooLong`] if `plaintext` is longer than [`MAX_PLAINTEXT_LEN`].
/// - [`SealError::WrongLabel`] if `aad` has a key-wrap label (use [`seal_key`]), or `nonce` is
///   not the kind FS-29 gives the label.
///
/// Nothing is sealed on an error.
pub fn seal(
    key: &SealKey,
    aad: &Aad,
    plaintext: &[u8],
    nonce: NonceKind<'_>,
) -> Result<Vec<u8>, SealError> {
    if aad.label().is_some_and(AadLabel::is_key_wrap) {
        return Err(SealError::WrongLabel);
    }
    seal_drawing(key, aad, plaintext, nonce, random::fill)
}

/// Wraps `key_to_wrap` under `key` with a hedged nonce, giving a 104-byte wrap (FS-29,
/// section 9.7).
///
/// # Errors
///
/// - [`SealError::Random`] if the kernel cannot supply randomness.
/// - [`SealError::WrongLabel`] if `aad` does not have a key-wrap label.
pub fn seal_key(
    key: &SealKey,
    aad: &Aad,
    key_to_wrap: &impl KeyMaterial,
) -> Result<Vec<u8>, SealError> {
    seal_key_drawing(key, aad, key_to_wrap, random::fill)
}

/// [`seal_key`] with its randomness drawn by `draw`, so tests can check the wrap's nonce.
fn seal_key_drawing(
    key: &SealKey,
    aad: &Aad,
    key_to_wrap: &impl KeyMaterial,
    draw: impl FnOnce(&mut [u8]) -> Result<(), RandomError>,
) -> Result<Vec<u8>, SealError> {
    if !aad.label().is_some_and(AadLabel::is_key_wrap) {
        return Err(SealError::WrongLabel);
    }
    let material = sealed::material(key_to_wrap);
    seal_drawing(key, aad, material, NonceKind::Hedged, draw)
}

/// Seals with a given nonce, for the test-vector runners only.
#[cfg(any(test, feature = "vectors"))]
#[cfg_attr(
    not(feature = "vectors"),
    expect(unreachable_pub, reason = "public only with `vectors`, for TV-05")
)]
#[must_use]
pub fn seal_with_nonce(key: &SealKey, aad: &Aad, plaintext: &[u8], nonce: &[u8; 24]) -> Vec<u8> {
    let a = hash::hash(HashLabel::CxAad, aad.as_bytes());
    seal_with_a(key, aad, &a, plaintext, nonce)
}

/// [`seal`] with its randomness drawn by `draw`, so tests can check which nonce each kind gets.
fn seal_drawing(
    key: &SealKey,
    aad: &Aad,
    plaintext: &[u8],
    nonce: NonceKind<'_>,
    draw: impl FnOnce(&mut [u8]) -> Result<(), RandomError>,
) -> Result<Vec<u8>, SealError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(SealError::TooLong);
    }
    // FS-29: shard headers, and only they, get synthetic nonces. Raw vector AADs carry no label.
    if let Some(label) = aad.label() {
        let synthetic = matches!(nonce, NonceKind::Synthetic(_));
        if synthetic != (label == AadLabel::ShardHeader) {
            return Err(SealError::WrongLabel);
        }
    }
    let a = hash::hash(HashLabel::CxAad, aad.as_bytes());
    let nonce = match nonce {
        NonceKind::Hedged => {
            let mut rand = [0u8; 32];
            draw(&mut rand)?;
            nonce::hedged_nonce(key, &a, plaintext, &rand)
        }
        NonceKind::Synthetic(nonce_key) => nonce::synthetic_nonce(nonce_key, &a, plaintext),
    };
    Ok(seal_with_a(key, aad, &a, plaintext, &nonce))
}

fn seal_with_a(
    key: &SealKey,
    aad: &Aad,
    a: &Hash32,
    plaintext: &[u8],
    nonce: &[u8; 24],
) -> Vec<u8> {
    let parts: [&[u8]; 2] = [nonce, a.as_bytes()];
    let commitment = kdf::expand(sealed::material(key), KdfLabel::CxCommit, &parts);
    let cipher = cipher(key, &parts);
    let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(commitment.as_slice());
    out.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(
            &XNonce::from(*nonce),
            aad.as_bytes(),
            (&mut out[NONCE_LEN + COMMITMENT_LEN..]).into(),
        )
        .expect("MAX_PLAINTEXT_LEN is far below the XChaCha20 limit of 256 GiB");
    out.extend_from_slice(tag.as_slice());
    out
}

/// XChaCha20-Poly1305 under `K_enc = HKDF-Expand(K, kdf/cx-key ‖ nonce ‖ a)`. The cipher wipes
/// its key on drop.
pub(super) fn cipher(key: &SealKey, nonce_and_a: &[&[u8]; 2]) -> XChaCha20Poly1305 {
    let enc_key = kdf::expand(sealed::material(key), KdfLabel::CxKey, nonce_and_a);
    XChaCha20Poly1305::new((&*enc_key).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ShardNonceKey;

    fn key() -> SealKey {
        sealed::from_material([1; 32])
    }

    fn aad() -> Aad {
        Aad::new(AadLabel::BlobData).field(&[9; 16])
    }

    fn a() -> Hash32 {
        hash::hash(HashLabel::CxAad, aad().as_bytes())
    }

    fn shard_aad() -> Aad {
        Aad::with_preamble(AadLabel::ShardHeader, &[2; 16]).u8(0)
    }

    fn wrap_aad() -> Aad {
        Aad::new(AadLabel::DekWrap).field(&[9; 16])
    }

    fn constant(byte: u8) -> impl FnOnce(&mut [u8]) -> Result<(), RandomError> {
        move |out| {
            out.fill(byte);
            Ok(())
        }
    }

    #[test]
    fn a_hedged_nonce_macs_the_drawn_bytes() {
        let sealed = seal_drawing(&key(), &aad(), b"pt", NonceKind::Hedged, constant(0x11));
        let nonce = nonce::hedged_nonce(&key(), &a(), b"pt", &[0x11; 32]);
        assert_eq!(sealed, Ok(seal_with_nonce(&key(), &aad(), b"pt", &nonce)));
    }

    #[test]
    fn a_synthetic_seal_draws_nothing_and_repeats() {
        let nonce_key: ShardNonceKey = sealed::from_material([3; 32]);
        let kind = NonceKind::Synthetic(&nonce_key);
        let never = |_: &mut [u8]| -> Result<(), RandomError> { panic!("a synthetic nonce drew") };
        let sealed = seal_drawing(&key(), &shard_aad(), b"header", kind, never);
        let a = hash::hash(HashLabel::CxAad, shard_aad().as_bytes());
        let nonce = nonce::synthetic_nonce(&nonce_key, &a, b"header");
        assert_eq!(
            sealed,
            Ok(seal_with_nonce(&key(), &shard_aad(), b"header", &nonce))
        );
        assert_eq!(
            seal(&key(), &shard_aad(), b"header", kind),
            sealed,
            "a rebuilt header differs"
        );
    }

    #[test]
    fn seal_draws_fresh_randomness_for_hedged_nonces() {
        let first = seal(&key(), &aad(), b"pt", NonceKind::Hedged).expect("getrandom works");
        let second = seal(&key(), &aad(), b"pt", NonceKind::Hedged).expect("getrandom works");
        assert_ne!(
            first[..NONCE_LEN],
            second[..NONCE_LEN],
            "a hedged nonce ignored getrandom"
        );
    }

    #[test]
    fn replayed_randomness_repeats_a_nonce_only_for_an_identical_seal() {
        // A VM restored without a VM generation ID replays getrandom (T-81).
        let seal_with = |aad: &Aad, plaintext: &[u8]| {
            let sealed = seal_drawing(&key(), aad, plaintext, NonceKind::Hedged, constant(0x44));
            sealed.expect("seals")
        };
        let other_aad = Aad::new(AadLabel::BlobData).field(&[8; 16]);
        let base = seal_with(&aad(), b"pt");
        assert_eq!(
            base,
            seal_with(&aad(), b"pt"),
            "an identical seal is identical"
        );
        assert_ne!(
            base[..NONCE_LEN],
            seal_with(&aad(), b"pT")[..NONCE_LEN],
            "plaintext ignored"
        );
        assert_ne!(
            base[..NONCE_LEN],
            seal_with(&other_aad, b"pt")[..NONCE_LEN],
            "AAD ignored"
        );
    }

    #[test]
    fn a_key_wrap_uses_a_hedged_nonce() {
        let wrapped: SealKey = sealed::from_material([6; 32]);
        let wrap = seal_key_drawing(&key(), &wrap_aad(), &wrapped, constant(0x33));
        let a = hash::hash(HashLabel::CxAad, wrap_aad().as_bytes());
        let nonce = nonce::hedged_nonce(&key(), &a, &[6; 32], &[0x33; 32]);
        assert_eq!(
            wrap,
            Ok(seal_with_nonce(&key(), &wrap_aad(), &[6; 32], &nonce))
        );
    }

    #[test]
    fn each_label_is_sealed_only_its_own_way() {
        let nonce_key: ShardNonceKey = sealed::from_material([3; 32]);
        let wrapped: SealKey = sealed::from_material([6; 32]);
        let wrong = Err(SealError::WrongLabel);
        assert_eq!(
            seal(&key(), &wrap_aad(), b"key bytes", NonceKind::Hedged),
            wrong,
            "wrap via seal"
        );
        assert_eq!(
            seal_key(&key(), &aad(), &wrapped),
            wrong,
            "data label via seal_key"
        );
        let synthetic = NonceKind::Synthetic(&nonce_key);
        assert_eq!(
            seal(&key(), &aad(), b"pt", synthetic),
            wrong,
            "synthetic outside headers"
        );
        assert_eq!(
            seal(&key(), &shard_aad(), b"pt", NonceKind::Hedged),
            wrong,
            "hedged header"
        );
    }

    #[test]
    fn a_failed_draw_seals_nothing() {
        let fail = |_: &mut [u8]| Err(RandomError);
        let result = seal_drawing(&key(), &aad(), b"pt", NonceKind::Hedged, fail);
        assert_eq!(result, Err(SealError::Random));
    }
}
