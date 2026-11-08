//! A user passphrase in protected memory.

use std::fmt;

use zeroize::Zeroize;

use crate::secure_mem::{MemError, SecretBuf};

/// A passphrase, the input of [`argon2id::derive`](crate::argon2id::derive).
///
/// Its bytes live in a [`SecretBuf`]: protected, wiped when dropped, and never printed. The bytes
/// are used as given: the caller decides any Unicode normalization.
pub struct Passphrase(SecretBuf);

impl Passphrase {
    /// Copies the passphrase into protected memory and wipes `text`, whether or not the copy
    /// could be made.
    ///
    /// # Errors
    ///
    /// The [`MemError`] of [`SecretBuf::try_copy_from`] if no protected memory for the copy can
    /// be had. `text` is wiped before the error is returned.
    pub fn new(mut text: String) -> Result<Self, MemError> {
        let copy = SecretBuf::try_copy_from(text.as_bytes());
        text.zeroize();
        copy.map(Self)
    }

    /// The passphrase bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_bytes_and_never_prints_them() {
        let passphrase = Passphrase::new("hunter2".to_owned()).expect("a buffer");
        assert_eq!(passphrase.as_bytes(), b"hunter2");
        assert_eq!(format!("{passphrase:?}"), "Passphrase(..)");
    }
}
