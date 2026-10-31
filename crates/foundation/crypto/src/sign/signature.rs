//! A 64-byte Ed25519 signature.

/// An Ed25519 signature `R ‖ S` (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature([u8; Signature::LEN]);

impl Signature {
    /// Length in bytes.
    pub const LEN: usize = 64;

    /// Wraps signature bytes read from a file. They are checked only by
    /// [`VerifyingKey::verify`](crate::sign::VerifyingKey::verify).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The `R` half.
    pub(crate) fn r_bytes(&self) -> [u8; 32] {
        let mut r = [0u8; 32];
        r.copy_from_slice(&self.0[..32]);
        r
    }
}
