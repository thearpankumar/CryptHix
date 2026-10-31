//! A user passphrase, wiped on drop.

use std::fmt;

use zeroize::ZeroizeOnDrop;

/// A passphrase, the input of [`argon2id::derive`](crate::argon2id::derive).
///
/// Its bytes are wiped when it is dropped, and it never prints. The bytes are used as given: the
/// caller decides any Unicode normalization.
#[derive(ZeroizeOnDrop)]
pub struct Passphrase(Vec<u8>);

impl Passphrase {
    /// Takes ownership of the passphrase text without copying it.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(text.into_bytes())
    }

    /// The passphrase bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(..)")
    }
}
