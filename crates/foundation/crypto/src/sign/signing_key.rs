//! An Ed25519 signing key.

use std::fmt;

use ed25519_dalek::Signer;
use zeroize::Zeroizing;

use crate::key::KeyMaterial;
use crate::key::sealed::{Sealed, Token};
use crate::label::SigLabel;
use crate::random::{self, RandomError};
use crate::sign::sig_input;
use crate::sign::{Signature, VerifyingKey};

/// An Ed25519 signing key: the vault master key or a device key (FS-36, FS-37).
///
/// Its 32-byte seed is wiped on drop and is used only for signing (FS-25). It can be wrapped
/// with [`cx_aead::seal_key`](crate::cx_aead::seal_key).
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// A new key from a 32-byte seed straight from the kernel (FS-01).
    ///
    /// # Errors
    ///
    /// [`RandomError`] if the kernel cannot supply randomness.
    pub fn random() -> Result<Self, RandomError> {
        let seed = Zeroizing::new(random::bytes::<32>()?);
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    /// Builds a key from a known seed, for the test-vector runners only.
    #[cfg(feature = "vectors")]
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_dalek(self.0.verifying_key())
    }

    /// Signs `body` under `label` and `ctx` (FS-13). The signer field of the input is this key's
    /// `key_id`.
    #[must_use]
    pub fn sign(&self, label: SigLabel, ctx: &[u8; 16], body: &[u8]) -> Signature {
        let input = sig_input::sig_input(label, ctx, &self.verifying_key().key_id(), body);
        Signature::from_bytes(self.0.sign(&input).to_bytes())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl Sealed for SigningKey {
    fn from_material(bytes: [u8; 32], _: Token) -> Self {
        let seed = Zeroizing::new(bytes);
        Self(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    fn material(&self, _: Token) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl KeyMaterial for SigningKey {}
