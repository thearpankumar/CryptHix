//! An Ed25519 public key with strict, canonical verification (FS-14).

use crypthix_types::format_error::FormatError;
use crypthix_types::id::KeyId;

use crate::hash;
use crate::label::{HashLabel, SigLabel};
use crate::sign::Signature;
use crate::sign::sig_input;

/// An Ed25519 public key that passed the checks of FS-14: canonically encoded and in the
/// prime-order subgroup, so it has neither a small order nor a torsion component.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Parses a 32-byte public key.
    ///
    /// # Errors
    ///
    /// [`FormatError::WeakKey`] if the bytes are not a point, are not its canonical encoding, or
    /// encode a point outside the prime-order subgroup: of small order, or with a torsion
    /// component (FS-14). A key made by [`SigningKey`](crate::sign::SigningKey) always passes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, FormatError> {
        let key = canonical_point(bytes).ok_or(FormatError::WeakKey)?;
        if key.is_weak() || !key.to_edwards().is_torsion_free() {
            return Err(FormatError::WeakKey);
        }
        Ok(Self(key))
    }

    pub(crate) fn from_dalek(key: ed25519_dalek::VerifyingKey) -> Self {
        Self(key)
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// `key_id = H(hash/key-id, public key)` (section 4.1).
    ///
    /// # Panics
    ///
    /// Never in practice: it would need a BLAKE3 output of all zeros.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        let id = hash::hash(HashLabel::KeyId, self.as_bytes());
        KeyId::try_from_bytes(*id.as_bytes()).expect("a BLAKE3 output is never all zero")
    }

    /// Verifies a signature made by [`SigningKey::sign`](crate::sign::SigningKey::sign) with the
    /// same `label`, `ctx` and `body` (FS-13, FS-14).
    ///
    /// # Errors
    ///
    /// [`FormatError::Signature`] if the signature is invalid, malleable or not canonical.
    pub fn verify(
        &self,
        label: SigLabel,
        ctx: &[u8; 16],
        body: &[u8],
        signature: &Signature,
    ) -> Result<(), FormatError> {
        self.verify_message(
            &sig_input::sig_input(label, ctx, &self.key_id(), body),
            signature,
        )
    }

    /// Verifies a signature over a raw message with the same strict rules as [`Self::verify`],
    /// for the Ed25519 known-answer runners only. Format code never verifies a raw message: the
    /// labelled input of FS-13 is what keeps one signature from being valid in two places.
    ///
    /// # Errors
    ///
    /// [`FormatError::Signature`] as for [`Self::verify`].
    #[cfg(feature = "vectors")]
    pub fn verify_raw(&self, message: &[u8], signature: &Signature) -> Result<(), FormatError> {
        self.verify_message(message, signature)
    }

    fn verify_message(&self, message: &[u8], signature: &Signature) -> Result<(), FormatError> {
        // `verify_strict` checks S < L, rejects small-order R and A, and compares the recomputed
        // R by its encoding. The canonical-R check repeats that last rule explicitly, as defence
        // in depth, so FS-14 does not rest on one library's internals.
        canonical_point(&signature.r_bytes()).ok_or(FormatError::Signature)?;
        let dalek = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
        self.0
            .verify_strict(message, &dalek)
            .map_err(|_| FormatError::Signature)
    }
}

/// Decodes a point and returns it only if re-encoding gives back the same bytes, so
/// non-canonical encodings fail (FS-14). For a public key this is defence in depth: every
/// non-canonical encoding of a point is also of small or mixed order, which `from_bytes`
/// rejects anyway.
fn canonical_point(bytes: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
    let point = ed25519_dalek::VerifyingKey::from_bytes(bytes).ok()?;
    (point.to_edwards().compress().to_bytes() == *bytes).then_some(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::sealed;
    use crate::sign::SigningKey;

    fn signer() -> SigningKey {
        sealed::from_material([3; 32])
    }

    #[test]
    fn identity_point_is_weak() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            VerifyingKey::from_bytes(&identity),
            Err(FormatError::WeakKey)
        );
    }

    #[test]
    fn non_canonical_encoding_is_weak() {
        // y = p + 1 encodes the same point as y = 1 (the identity) non-canonically.
        let mut bytes = [0xffu8; 32];
        bytes[0] = 0xee;
        bytes[31] = 0x7f;
        assert_eq!(VerifyingKey::from_bytes(&bytes), Err(FormatError::WeakKey));
    }

    #[test]
    fn mixed_order_key_is_weak() {
        // A valid key plus the order-2 point (0, -1): not small order, but not torsion-free.
        let public = signer().verifying_key().0.to_edwards();
        let mut order_two = [0u8; 32];
        order_two[0] = 0xec;
        order_two[1..31].fill(0xff);
        order_two[31] = 0x7f;
        let torsion = ed25519_dalek::VerifyingKey::from_bytes(&order_two)
            .expect("a point")
            .to_edwards();
        let mixed = (public + torsion).compress().to_bytes();
        assert_eq!(VerifyingKey::from_bytes(&mixed), Err(FormatError::WeakKey));
    }

    #[test]
    fn a_valid_key_round_trips() {
        let public = signer().verifying_key();
        assert_eq!(VerifyingKey::from_bytes(public.as_bytes()), Ok(public));
    }

    #[test]
    fn every_input_field_is_bound() {
        let signer = signer();
        let public = signer.verifying_key();
        let signature = signer.sign(SigLabel::Manifest, &[1; 16], b"body");
        assert!(
            public
                .verify(SigLabel::Manifest, &[1; 16], b"body", &signature)
                .is_ok()
        );
        let failures = [
            public.verify(SigLabel::Root, &[1; 16], b"body", &signature),
            public.verify(SigLabel::Manifest, &[2; 16], b"body", &signature),
            public.verify(SigLabel::Manifest, &[1; 16], b"bodY", &signature),
            sealed::from_material::<SigningKey>([4; 32])
                .verifying_key()
                .verify(SigLabel::Manifest, &[1; 16], b"body", &signature),
        ];
        for failure in failures {
            assert_eq!(failure, Err(FormatError::Signature));
        }
    }

    #[test]
    fn s_at_or_above_the_group_order_fails() {
        let signer = signer();
        let signature = signer.sign(SigLabel::Root, &[0; 16], b"x");
        let mut bytes = *signature.as_bytes();
        bytes[63] |= 0xf0;
        let result = signer.verifying_key().verify(
            SigLabel::Root,
            &[0; 16],
            b"x",
            &Signature::from_bytes(bytes),
        );
        assert_eq!(result, Err(FormatError::Signature));
    }
}
