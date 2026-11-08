//! Open (FS-28).

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{Tag, XNonce};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crypthix_types::format_error::FormatError;

use crate::aad::Aad;
use crate::cx_aead::open_cause::OpenCause;
use crate::cx_aead::open_error::OpenError;
use crate::cx_aead::seal;
use crate::cx_aead::{COMMITMENT_LEN, NONCE_LEN, TAG_LEN, WRAPPED_KEY_LEN};
use crate::hash::{self, Hash32};
use crate::kdf;
use crate::key::check_nonzero;
use crate::key::sealed;
use crate::key::{KeyError, KeyMaterial, SealKey};
use crate::label::{AadLabel, HashLabel, KdfLabel};
use crate::secure_mem::SecretBuf;

/// Opens a sealed field and returns its plaintext in protected memory, wiped when dropped (O1).
///
/// The plaintext buffer is made only once the key commitment holds, so input that was never
/// sealed under `key`, this nonce and `aad` costs no protected memory. Input that reuses a
/// genuine nonce and commitment with a changed body still gets a buffer, wiped when its tag
/// fails.
///
/// # Errors
///
/// - [`OpenError::Format`] with:
///   - `Truncated` if `sealed` is shorter than the 72-byte overhead;
///   - `ZeroValue` if the nonce is all zero (FS-03);
///   - `Decrypt` for any change to the key, nonce, AAD, ciphertext or tag (FS-28), and for an
///     AAD with a key-wrap label: a wrapped key opens only through [`open_key`], so its bytes
///     never leave the crate.
/// - [`OpenError::Memory`] if the commitment holds but the kernel maps no buffer for the
///   plaintext ([`SecretBuf::try_zeroed`]). Never `Decrypt`, so memory pressure does not look
///   like tampering.
///
/// # Panics
///
/// On Linux, in a child forked without `exec` after `key` was made
/// ([`secure_mem`](crate::secure_mem#fork)).
pub fn open(key: &SealKey, aad: &Aad, sealed: &[u8]) -> Result<SecretBuf, OpenError> {
    if aad.label().is_some_and(AadLabel::is_key_wrap) {
        return Err(FormatError::Decrypt.into());
    }
    open_detailed(key, aad, sealed).map_err(OpenCause::opaque)
}

/// Unwraps a key wrapped by [`seal_key`](crate::cx_aead::seal_key), decrypting it straight into
/// its slot of protected memory.
///
/// # Errors
///
/// - [`KeyError::Format`] with:
///   - `Truncated` or `TrailingBytes` if `sealed` is not 104 bytes;
///   - `Decrypt` if the wrap does not open, or `aad` does not have a key-wrap label, so data
///     sealed with [`seal`](fn@crate::cx_aead::seal) cannot become a key;
///   - `ZeroValue` if the unwrapped key is all zero (FS-03).
/// - [`KeyError::Memory`] if no protected memory is free. The slot is taken after the length
///   and label checks but before the wrap is opened, so this never depends on the wrap's bytes.
///   Unlike [`open`], whose buffer waits for the commitment, this costs one 32-byte slot even
///   for a forged wrap; the slot is wiped and freed again on any error.
///
/// # Panics
///
/// On Linux, in a child forked without `exec` after `key` was made
/// ([`secure_mem`](crate::secure_mem#fork)).
pub fn open_key<K: KeyMaterial>(key: &SealKey, aad: &Aad, sealed: &[u8]) -> Result<K, KeyError> {
    match sealed.len() {
        len if len < WRAPPED_KEY_LEN => return Err(FormatError::Truncated.into()),
        len if len > WRAPPED_KEY_LEN => return Err(FormatError::TrailingBytes.into()),
        _ => {}
    }
    if !aad.label().is_some_and(AadLabel::is_key_wrap) {
        return Err(FormatError::Decrypt.into());
    }
    sealed::new_with(|material| {
        let parts = Parts::split(sealed).map_err(OpenCause::opaque)?;
        parts
            .open_into(key, aad, material)
            .map_err(OpenCause::opaque)?;
        check_nonzero::check_nonzero(material)?;
        Ok::<(), KeyError>(())
    })
}

/// Opens a sealed field and reports which check failed, for the TV-05 runner only.
///
/// # Errors
///
/// [`OpenCause`]: `Truncated`, `ZeroNonce`, then `Commitment` (checked before the tag, and
/// before the plaintext buffer is made), then `Memory` if no buffer can be had, then `AeadTag`.
///
/// # Panics
///
/// On Linux, in a child forked without `exec` after `key` was made
/// ([`secure_mem`](crate::secure_mem#fork)).
#[cfg_attr(
    not(feature = "vectors"),
    expect(unreachable_pub, reason = "public only with `vectors`, for TV-05")
)]
pub fn open_detailed(key: &SealKey, aad: &Aad, sealed: &[u8]) -> Result<SecretBuf, OpenCause> {
    let parts = Parts::split(sealed)?;
    let a = parts.check_commitment(key, aad)?;
    let mut plaintext = SecretBuf::try_zeroed(parts.ciphertext.len()).map_err(OpenCause::Memory)?;
    parts.decrypt_into(key, aad, &a, plaintext.as_mut_slice())?;
    Ok(plaintext)
}

/// The fields of `nonce ‖ C ‖ ct ‖ tag`.
struct Parts<'a> {
    nonce: &'a [u8; NONCE_LEN],
    commitment: &'a [u8; COMMITMENT_LEN],
    ciphertext: &'a [u8],
    tag: &'a [u8; TAG_LEN],
}

impl<'a> Parts<'a> {
    /// Splits a seal, rejecting one shorter than the overhead or with an all-zero nonce.
    fn split(sealed: &'a [u8]) -> Result<Self, OpenCause> {
        let Some((nonce, rest)) = sealed.split_first_chunk::<NONCE_LEN>() else {
            return Err(OpenCause::Truncated);
        };
        let Some((commitment, rest)) = rest.split_first_chunk::<COMMITMENT_LEN>() else {
            return Err(OpenCause::Truncated);
        };
        let Some((ciphertext, tag)) = rest.split_last_chunk::<TAG_LEN>() else {
            return Err(OpenCause::Truncated);
        };
        if *nonce == [0u8; NONCE_LEN] {
            return Err(OpenCause::ZeroNonce);
        }
        Ok(Self {
            nonce,
            commitment,
            ciphertext,
            tag,
        })
    }

    /// Checks the commitment, then decrypts into `out`, which has the ciphertext's length. On
    /// failure `out` is wiped.
    fn open_into(&self, key: &SealKey, aad: &Aad, out: &mut [u8]) -> Result<(), OpenCause> {
        let a = self.check_commitment(key, aad)?;
        self.decrypt_into(key, aad, &a, out)
    }

    /// Checks the key commitment, which needs no output buffer, and returns `a = H(cx-aad, aad)`
    /// for [`decrypt_into`](Parts::decrypt_into).
    fn check_commitment(&self, key: &SealKey, aad: &Aad) -> Result<Hash32, OpenCause> {
        let a = hash::hash(HashLabel::CxAad, aad.as_bytes());
        let parts: [&[u8]; 2] = [self.nonce, a.as_bytes()];
        let expected = kdf::expand(sealed::material(key), KdfLabel::CxCommit, &parts);
        if bool::from(expected.as_slice().ct_eq(self.commitment)) {
            Ok(a)
        } else {
            Err(OpenCause::Commitment)
        }
    }

    /// Decrypts into `out`, which has the ciphertext's length, once
    /// [`check_commitment`](Parts::check_commitment) returned `a`. On failure `out` is wiped.
    fn decrypt_into(
        &self,
        key: &SealKey,
        aad: &Aad,
        a: &Hash32,
        out: &mut [u8],
    ) -> Result<(), OpenCause> {
        let parts: [&[u8]; 2] = [self.nonce, a.as_bytes()];
        // The cipher checks the tag before it decrypts, so on a failed tag `out` still holds
        // ciphertext; it is wiped anyway.
        out.copy_from_slice(self.ciphertext);
        seal::cipher(key, &parts)
            .decrypt_inout_detached(
                &XNonce::from(*self.nonce),
                aad.as_bytes(),
                out.into(),
                &Tag::from(*self.tag),
            )
            .map_err(|_| {
                out.zeroize();
                OpenCause::AeadTag
            })
    }
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
            open_detailed(&key(2), &aad(), &sealed).err(),
            Some(OpenCause::Commitment)
        );
        let other_aad = Aad::new(AadLabel::BlobData).field(&[8; 16]);
        assert_eq!(
            open_detailed(&key(1), &other_aad, &sealed).err(),
            Some(OpenCause::Commitment)
        );
        for index in [0, NONCE_LEN - 1, NONCE_LEN, NONCE_LEN + COMMITMENT_LEN - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert_eq!(
                open_detailed(&key(1), &aad(), &tampered).err(),
                Some(OpenCause::Commitment),
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
                open_detailed(&key(1), &aad(), &tampered).err(),
                Some(OpenCause::AeadTag),
                "byte {index}"
            );
        }
    }

    /// The caller's buffer, filled with other bytes first, holds neither them nor the
    /// ciphertext after a failed tag: `decrypt_into` copies the ciphertext in before the check,
    /// so without the wipe both would show.
    #[test]
    fn a_failed_tag_wipes_the_output() {
        let mut tampered = sealed_hello();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let parts = Parts::split(&tampered).expect("well formed");
        let a = parts
            .check_commitment(&key(1), &aad())
            .expect("the commitment holds");
        let mut out = [0x5a; 5];
        assert_eq!(
            parts.decrypt_into(&key(1), &aad(), &a, &mut out),
            Err(OpenCause::AeadTag)
        );
        assert_eq!(out, [0; 5]);
        let mut out = [0x5a; 5];
        assert_eq!(
            parts.open_into(&key(1), &aad(), &mut out),
            Err(OpenCause::AeadTag)
        );
        assert_eq!(out, [0; 5], "open_key's path wipes too");
        let mut out = [0x5a; 5];
        let good = sealed_hello();
        let parts = Parts::split(&good).expect("well formed");
        parts
            .open_into(&key(1), &aad(), &mut out)
            .expect("an untouched seal opens");
        assert_eq!(&out, b"hello", "the buffer is written");
    }

    #[test]
    fn outside_callers_see_only_decrypt() {
        let sealed = sealed_hello();
        let mut tampered = sealed.clone();
        tampered[NONCE_LEN + COMMITMENT_LEN] ^= 1;
        assert_eq!(
            open(&key(2), &aad(), &sealed).err(),
            Some(OpenError::Format(FormatError::Decrypt))
        );
        assert_eq!(
            open(&key(1), &aad(), &tampered).err(),
            Some(OpenError::Format(FormatError::Decrypt))
        );
        assert_eq!(
            open(&key(1), &aad(), &sealed[..OVERHEAD - 1]).err(),
            Some(OpenError::Format(FormatError::Truncated))
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
            Some(KeyError::Format(FormatError::Truncated))
        );
        let mut long = wrap;
        long.push(0);
        assert_eq!(
            open_key::<KdfKey>(&key(1), &wrap_aad(), &long).err(),
            Some(KeyError::Format(FormatError::TrailingBytes))
        );
    }

    #[test]
    fn an_all_zero_unwrapped_key_is_rejected() {
        let zero: KdfKey = sealed::from_material([0; 32]);
        let wrap = seal::seal_key(&key(1), &wrap_aad(), &zero).expect("getrandom works");
        assert_eq!(
            open_key::<KdfKey>(&key(1), &wrap_aad(), &wrap).err(),
            Some(KeyError::Format(FormatError::ZeroValue))
        );
    }

    #[test]
    fn wrapped_keys_and_data_do_not_cross() {
        let dek: KdfKey = sealed::from_material([7; 32]);
        let wrap = seal::seal_key(&key(1), &wrap_aad(), &dek).expect("getrandom works");
        assert_eq!(
            open(&key(1), &wrap_aad(), &wrap).err(),
            Some(OpenError::Format(FormatError::Decrypt)),
            "read a key"
        );
        let chosen = seal::seal_with_nonce(&key(1), &aad(), &[7; 32], &[5; 24]);
        let forged = open_key::<KdfKey>(&key(1), &aad(), &chosen).err();
        assert_eq!(
            forged,
            Some(KeyError::Format(FormatError::Decrypt)),
            "forged a key from chosen bytes"
        );
    }

    #[test]
    fn an_all_zero_nonce_is_a_zero_value() {
        let mut sealed = sealed_hello();
        sealed[..NONCE_LEN].fill(0);
        assert_eq!(
            open_detailed(&key(1), &aad(), &sealed).err(),
            Some(OpenCause::ZeroNonce)
        );
        assert_eq!(
            open(&key(1), &aad(), &sealed).err(),
            Some(OpenError::Format(FormatError::ZeroValue))
        );
    }
}
