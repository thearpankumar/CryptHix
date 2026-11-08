//! An Ed25519 signing key.

use std::fmt;

use ed25519_dalek::Signer;

use crate::key::KeyError;
use crate::key::KeyMaterial;
use crate::key::sealed::{self, Sealed, Token};
use crate::label::SigLabel;
use crate::secure_mem::{self, KeySlot, Level, MemError};
use crate::sign::sig_input;
use crate::sign::{Signature, VerifyingKey};

/// An Ed25519 signing key: the vault master key or a device key (FS-36, FS-37).
///
/// Its 32-byte seed lives in protected memory (O1), is wiped on drop and is used only for
/// signing (FS-25). It can be wrapped with [`cx_aead::seal_key`](crate::cx_aead::seal_key).
pub struct SigningKey(KeySlot);

impl SigningKey {
    /// A new key from a 32-byte seed straight from the kernel (FS-01).
    ///
    /// # Errors
    ///
    /// - [`KeyError::Random`] if the kernel cannot supply randomness.
    /// - [`KeyError::Memory`] if no protected memory is free.
    pub fn random() -> Result<Self, KeyError> {
        sealed::new_random()
    }

    /// Builds a key from a known seed, for the test-vector runners only.
    ///
    /// # Errors
    ///
    /// [`KeyError::Memory`] if no protected memory is free.
    #[cfg(feature = "vectors")]
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, KeyError> {
        sealed::new_with(|material| {
            *material = *seed;
            Ok::<(), KeyError>(())
        })
    }

    /// The public key.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the key was made
    /// ([`secure_mem`](crate::secure_mem#fork)).
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.with_expanded(|key| VerifyingKey::from_dalek(key.verifying_key()))
    }

    /// Signs `body` under `label` and `ctx` (FS-13). The signer field of the input is this key's
    /// `key_id`. The seed is expanded once for both.
    ///
    /// The body may be plaintext, so the signature input is built in a
    /// [`SecretBuf`](crate::secure_mem::SecretBuf): the body with its label, context, signer and
    /// length.
    ///
    /// # Errors
    ///
    /// The [`MemError`] of [`SecretBuf::try_zeroed`](crate::secure_mem::SecretBuf::try_zeroed)
    /// if no buffer for the signature input can be had: `MapFailed`, or `TooLarge` for a body
    /// near `isize::MAX` bytes. Signing itself cannot fail.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the key was made
    /// ([`secure_mem`](crate::secure_mem#fork)).
    pub fn sign(
        &self,
        label: SigLabel,
        ctx: &[u8; 16],
        body: &[u8],
    ) -> Result<Signature, MemError> {
        self.with_expanded(|key| {
            let key_id = VerifyingKey::from_dalek(key.verifying_key()).key_id();
            let input = sig_input::sig_input(label, ctx, &key_id, body)?;
            Ok(Signature::from_bytes(key.sign(input.as_slice()).to_bytes()))
        })
    }

    /// The protection the seed's memory got.
    #[must_use]
    pub fn level(&self) -> Level {
        self.0.level()
    }

    /// Runs `f` on the dalek key, expanded from the seed for this one call.
    ///
    /// The dalek key is built and dropped in this frame and only lent to `f`, so this code never
    /// moves it; its `Drop` (`ZeroizeOnDrop` with the `zeroize` feature) wipes it at its final
    /// location. Copies left by moves while it is built (`from_bytes` returns it by value) and
    /// by the signing code spilling to the stack are short-lived and not reliably wiped (see
    /// [`secure_mem`](crate::secure_mem#what-this-does-not-cover)). Only the seed is kept, in
    /// protected memory.
    fn with_expanded<R>(&self, f: impl FnOnce(&ed25519_dalek::SigningKey) -> R) -> R {
        let key = ed25519_dalek::SigningKey::from_bytes(self.0.bytes());
        f(&key)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl Sealed for SigningKey {
    fn zeroed(_: Token) -> Result<Self, MemError> {
        secure_mem::take_key_slot().map(Self)
    }

    fn material(&self, _: Token) -> &[u8; 32] {
        self.0.bytes()
    }

    fn material_mut(&mut self, _: Token) -> &mut [u8; 32] {
        self.0.bytes_mut()
    }
}

impl KeyMaterial for SigningKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aad::Aad;
    use crate::cx_aead;
    use crate::key::SealKey;
    use crate::label::AadLabel;

    #[test]
    fn the_expanded_key_is_the_one_of_the_seed() {
        let key: SigningKey = sealed::from_material([3; 32]);
        let dalek = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        assert_eq!(
            key.with_expanded(ed25519_dalek::SigningKey::verifying_key),
            dalek.verifying_key()
        );
        assert_eq!(
            key.verifying_key(),
            VerifyingKey::from_dalek(dalek.verifying_key())
        );
    }

    /// A wrap carries the seed itself, so the key it opens to is the same key.
    #[test]
    fn a_wrapped_key_opens_to_the_same_seed() {
        let wrapping: SealKey = sealed::from_material([1; 32]);
        let aad = Aad::new(AadLabel::VaultSignKey).field(&[9; 16]);
        let key: SigningKey = sealed::from_material([3; 32]);
        let wrap = cx_aead::seal_key(&wrapping, &aad, &key).expect("getrandom works");
        let opened: SigningKey = cx_aead::open_key(&wrapping, &aad, &wrap).expect("opens");
        assert_eq!(sealed::material(&opened), &[3; 32]);
        assert_eq!(opened.verifying_key(), key.verifying_key());
    }

    #[test]
    fn a_signature_binds_the_signer_id_of_its_own_key() {
        let key: SigningKey = sealed::from_material([3; 32]);
        let signature = key.sign(SigLabel::Root, &[1; 16], b"body").expect("signs");
        let verifier = key.verifying_key();
        let dalek = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let input = sig_input::sig_input(SigLabel::Root, &[1; 16], &verifier.key_id(), b"body")
            .expect("a buffer");
        assert_eq!(
            signature.as_bytes(),
            &dalek.sign(input.as_slice()).to_bytes(),
            "Ed25519 is deterministic, so the same key over the same input signs alike"
        );
        assert!(
            verifier
                .verify(SigLabel::Root, &[1; 16], b"body", &signature)
                .is_ok()
        );
    }
}
