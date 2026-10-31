//! Open (FS-28).

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{Tag, XNonce};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crypthix_types::format_error::FormatError;

use crate::aad::Aad;
use crate::cx_aead::open_error::OpenError;
use crate::cx_aead::seal;
use crate::cx_aead::{COMMITMENT_LEN, NONCE_LEN, TAG_LEN, WRAPPED_KEY_LEN};
use crate::hash;
use crate::kdf;
use crate::key::check_nonzero;
use crate::key::sealed;
use crate::key::{KeyMaterial, SealKey};
use crate::label::{AadLabel, HashLabel, KdfLabel};

/// Opens a sealed field and returns its plaintext, which is wiped when dropped.
///
/// # Errors
///
/// - [`FormatError::Truncated`] if `sealed` is shorter than the 72-byte overhead.
/// - [`FormatError::ZeroValue`] if the nonce is all zero (FS-03).
/// - [`FormatError::Decrypt`] for any change to the key, nonce, AAD, ciphertext or tag (FS-28),
///   and for an AAD with a key-wrap label: a wrapped key opens only through [`open_key`], so its
///   bytes never leave the crate.
pub fn open(key: &SealKey, aad: &Aad, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    if aad.label().is_some_and(AadLabel::is_key_wrap) {
        return Err(FormatError::Decrypt);
    }
    open_detailed(key, aad, sealed).map_err(OpenError::opaque)
}

/// Unwraps a key wrapped by [`seal_key`](crate::cx_aead::seal_key).
///
/// # Errors
///
/// - [`FormatError::Truncated`] or [`FormatError::TrailingBytes`] if `sealed` is not 104 bytes.
/// - [`FormatError::Decrypt`] if the wrap does not open, or `aad` does not have a key-wrap
///   label, so data sealed with [`seal`](crate::cx_aead::seal) cannot become a key.
/// - [`FormatError::ZeroValue`] if the unwrapped key is all zero (FS-03).
pub fn open_key<K: KeyMaterial>(key: &SealKey, aad: &Aad, sealed: &[u8]) -> Result<K, FormatError> {
    match sealed.len() {
        len if len < WRAPPED_KEY_LEN => return Err(FormatError::Truncated),
        len if len > WRAPPED_KEY_LEN => return Err(FormatError::TrailingBytes),
        _ => {}
    }
    if !aad.label().is_some_and(AadLabel::is_key_wrap) {
        return Err(FormatError::Decrypt);
    }
    let plaintext = open_detailed(key, aad, sealed).map_err(OpenError::opaque)?;
    let mut material = Zeroizing::new([0u8; 32]);
    material.copy_from_slice(&plaintext);
    check_nonzero::check_nonzero(&material)?;
    Ok(sealed::from_material(*material))
}

/// Opens a sealed field and reports which check failed, for the TV-05 runner only.
///
/// # Errors
///
/// [`OpenError`]: `Truncated`, `ZeroNonce`, then `Commitment` (checked before the tag), then
/// `AeadTag`.
#[cfg_attr(
    not(feature = "vectors"),
    expect(unreachable_pub, reason = "public only with `vectors`, for TV-05")
)]
pub fn open_detailed(
    key: &SealKey,
    aad: &Aad,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let Some((nonce, rest)) = sealed.split_first_chunk::<NONCE_LEN>() else {
        return Err(OpenError::Truncated);
    };
    let Some((commitment, rest)) = rest.split_first_chunk::<COMMITMENT_LEN>() else {
        return Err(OpenError::Truncated);
    };
    let Some((ciphertext, tag)) = rest.split_last_chunk::<TAG_LEN>() else {
        return Err(OpenError::Truncated);
    };
    if *nonce == [0u8; NONCE_LEN] {
        return Err(OpenError::ZeroNonce);
    }

    let a = hash::hash(HashLabel::CxAad, aad.as_bytes());
    let parts: [&[u8]; 2] = [nonce, a.as_bytes()];
    let expected = kdf::expand(sealed::material(key), KdfLabel::CxCommit, &parts);
    if !bool::from(expected.as_slice().ct_eq(commitment)) {
        return Err(OpenError::Commitment);
    }

    // The cipher checks the tag before it decrypts, so a failed open leaves the ciphertext
    // untouched; the buffer is wiped on drop either way.
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    seal::cipher(key, &parts)
        .decrypt_inout_detached(
            &XNonce::from(*nonce),
            aad.as_bytes(),
            plaintext.as_mut_slice().into(),
            &Tag::from(*tag),
        )
        .map_err(|_| OpenError::AeadTag)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx_aead::{NonceKind, OVERHEAD};
    use crate::key::{KdfKey, ShardNonceKey};
    use crate::label::AadLabel;

    fn key(byte: u8) -> SealKey {
        sealed::from_material([byte; 32])
    }

    fn aad() -> Aad {
        Aad::new(AadLabel::BlobData).field(&[9; 16])
    }

    fn wrap_aad() -> Aad {
        Aad::new(AadLabel::DekWrap).field(&[9; 16])
    }

    fn sealed_hello() -> Vec<u8> {
        seal::seal_with_nonce(&key(1), &aad(), b"hello", &[5; 24])
    }

    #[test]
    fn round_trip_for_every_nonce_kind() {
        let shard_nonce: ShardNonceKey = sealed::from_material([4; 32]);
        let shard_aad = Aad::with_preamble(AadLabel::ShardHeader, &[2; 16]).u8(0);
        for (kind, aad) in [
            (NonceKind::Hedged, aad()),
            (NonceKind::Synthetic(&shard_nonce), shard_aad),
        ] {
            let sealed = seal::seal(&key(1), &aad, b"hello", kind).expect("getrandom works");
            assert_eq!(sealed.len(), OVERHEAD + 5);
            let opened = open(&key(1), &aad, &sealed).expect("opens");
            assert_eq!(opened.as_slice(), b"hello", "{kind:?}");
        }
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let sealed = seal::seal(&key(1), &aad(), b"", NonceKind::Hedged).expect("getrandom works");
        assert_eq!(sealed.len(), OVERHEAD);
        assert_eq!(
            open(&key(1), &aad(), &sealed).expect("opens").as_slice(),
            b""
        );
    }

    #[test]
    fn key_nonce_and_aad_changes_fail_the_commitment() {
        let sealed = sealed_hello();
        assert_eq!(
            open_detailed(&key(2), &aad(), &sealed),
            Err(OpenError::Commitment)
        );
        let other_aad = Aad::new(AadLabel::BlobData).field(&[8; 16]);
        assert_eq!(
            open_detailed(&key(1), &other_aad, &sealed),
            Err(OpenError::Commitment)
        );
        for index in [0, NONCE_LEN - 1, NONCE_LEN, NONCE_LEN + COMMITMENT_LEN - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert_eq!(
                open_detailed(&key(1), &aad(), &tampered),
                Err(OpenError::Commitment),
                "byte {index}"
            );
        }
    }

    #[test]
    fn ciphertext_and_tag_changes_fail_the_tag() {
        let sealed = sealed_hello();
        for index in [NONCE_LEN + COMMITMENT_LEN, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert_eq!(
                open_detailed(&key(1), &aad(), &tampered),
                Err(OpenError::AeadTag),
                "byte {index}"
            );
        }
    }

    #[test]
    fn outside_callers_see_only_decrypt() {
        let sealed = sealed_hello();
        let mut tampered = sealed.clone();
        tampered[NONCE_LEN + COMMITMENT_LEN] ^= 1;
        assert_eq!(
            open(&key(2), &aad(), &sealed).err(),
            Some(FormatError::Decrypt)
        );
        assert_eq!(
            open(&key(1), &aad(), &tampered).err(),
            Some(FormatError::Decrypt)
        );
        assert_eq!(
            open(&key(1), &aad(), &sealed[..OVERHEAD - 1]).err(),
            Some(FormatError::Truncated)
        );
    }

    #[test]
    fn key_wraps_are_104_bytes_and_round_trip() {
        let dek: KdfKey = sealed::from_material([7; 32]);
        let wrap = seal::seal_key(&key(1), &wrap_aad(), &dek).expect("getrandom works");
        assert_eq!(wrap.len(), WRAPPED_KEY_LEN);
        assert_eq!(WRAPPED_KEY_LEN, 104);
        let unwrapped: KdfKey = open_key(&key(1), &wrap_aad(), &wrap).expect("opens");
        assert_eq!(sealed::material(&unwrapped), &[7; 32]);
        assert_eq!(
            open_key::<KdfKey>(&key(1), &wrap_aad(), &wrap[..103]).err(),
            Some(FormatError::Truncated)
        );
        let mut long = wrap;
        long.push(0);
        assert_eq!(
            open_key::<KdfKey>(&key(1), &wrap_aad(), &long).err(),
            Some(FormatError::TrailingBytes)
        );
    }

    #[test]
    fn an_all_zero_unwrapped_key_is_rejected() {
        let zero: KdfKey = sealed::from_material([0; 32]);
        let wrap = seal::seal_key(&key(1), &wrap_aad(), &zero).expect("getrandom works");
        assert_eq!(
            open_key::<KdfKey>(&key(1), &wrap_aad(), &wrap).err(),
            Some(FormatError::ZeroValue)
        );
    }

    #[test]
    fn wrapped_keys_and_data_do_not_cross() {
        let dek: KdfKey = sealed::from_material([7; 32]);
        let wrap = seal::seal_key(&key(1), &wrap_aad(), &dek).expect("getrandom works");
        assert_eq!(
            open(&key(1), &wrap_aad(), &wrap).err(),
            Some(FormatError::Decrypt),
            "read a key"
        );
        let chosen = seal::seal_with_nonce(&key(1), &aad(), &[7; 32], &[5; 24]);
        let forged = open_key::<KdfKey>(&key(1), &aad(), &chosen).err();
        assert_eq!(
            forged,
            Some(FormatError::Decrypt),
            "forged a key from chosen bytes"
        );
    }

    #[test]
    fn an_all_zero_nonce_is_a_zero_value() {
        let mut sealed = sealed_hello();
        sealed[..NONCE_LEN].fill(0);
        assert_eq!(
            open_detailed(&key(1), &aad(), &sealed),
            Err(OpenError::ZeroNonce)
        );
        assert_eq!(
            open(&key(1), &aad(), &sealed).err(),
            Some(FormatError::ZeroValue)
        );
    }
}
