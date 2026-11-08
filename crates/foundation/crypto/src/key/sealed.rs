//! The private supertrait behind [`KeyMaterial`](crate::key::KeyMaterial) and the outputs of
//! [`kdf`](crate::kdf::kdf).
//!
//! The module is private to the crate, so other crates cannot name [`Token`], and without a
//! `Token` they cannot call the methods that read or build key bytes, even through a generic
//! bound on a public subtrait.

use std::num::NonZeroU8;

use crate::key::KeyError;
use crate::random;
use crate::secure_mem::MemError;

/// Proof that the caller is inside this crate. The non-zero field makes it impossible to
/// conjure with `mem::zeroed`, which panics for a type that has no all-zero value.
#[derive(Clone, Copy, Debug)]
pub struct Token(#[expect(dead_code, reason = "only its non-zero niche matters")] NonZeroU8);

/// The token, for this crate's own calls.
pub(crate) const TOKEN: Token = Token(NonZeroU8::MIN);

/// Access to the 32 bytes of a key or derived value, for this crate only.
///
/// A key is made zeroed in its protected slot and then filled in place, so its bytes are never
/// moved through a by-value array on the stack.
pub trait Sealed: Sized {
    /// A value of 32 zero bytes, in protected memory for a key (O1).
    ///
    /// # Errors
    ///
    /// [`MemError`] if no protected memory at the required level is free.
    fn zeroed(token: Token) -> Result<Self, MemError>;

    /// The 32 bytes.
    fn material(&self, token: Token) -> &[u8; 32];

    /// The 32 bytes, to fill in place.
    fn material_mut(&mut self, token: Token) -> &mut [u8; 32];
}

/// The bytes of `key`.
pub(crate) fn material<K: Sealed>(key: &K) -> &[u8; 32] {
    key.material(TOKEN)
}

/// A `K` whose bytes `fill` writes in place. If `fill` fails, the half-made key is wiped.
///
/// # Errors
///
/// [`MemError`] (through `E`) if no slot is free, or `fill`'s error.
pub(crate) fn new_with<K: Sealed, E: From<MemError>>(
    fill: impl FnOnce(&mut [u8; 32]) -> Result<(), E>,
) -> Result<K, E> {
    let mut key = K::zeroed(TOKEN)?;
    fill(key.material_mut(TOKEN))?;
    Ok(key)
}

/// A `K` of 32 bytes from `getrandom`, written straight into its slot, so no copy of them lands
/// on the stack.
///
/// This works in `memfd_secret` pages too, whichever way the bytes arrive. The `getrandom` system
/// call copies into user memory, which secret pages allow (see
/// [`secure_mem`](crate::secure_mem#why-plaintext-stays-out-of-secret-memory)). Since glibc 2.41,
/// on kernels with the vDSO `getrandom` (Linux 6.11), libc may instead generate the bytes in user
/// mode and store them with ordinary writes; that is safe here too, unlike in the mapping code's
/// `fault_in`, because every page of a secret arena was faulted in through the raw system call
/// when it was mapped, and secret pages are never reclaimed while mapped, so no write to a slot
/// can fault. Other levels are ordinary anonymous memory, which any write may fault in.
///
/// # Errors
///
/// [`KeyError::Random`] if the kernel cannot supply randomness, [`KeyError::Memory`] if no slot
/// is free.
pub(crate) fn new_random<K: Sealed>() -> Result<K, KeyError> {
    new_with(|material| {
        random::fill(material)?;
        Ok(())
    })
}

/// A `K` holding a copy of `bytes`, for unit tests.
#[cfg(test)]
pub(crate) fn from_material<K: Sealed>(bytes: [u8; 32]) -> K {
    new_with(|material| {
        *material = bytes;
        Ok::<(), MemError>(())
    })
    .expect("tests have protected memory")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::SealKey;

    #[test]
    fn random_keys_differ_and_are_not_zero() {
        let first: SealKey = new_random().expect("random key");
        let second: SealKey = new_random().expect("random key");
        assert_ne!(material(&first), &[0; 32]);
        assert_ne!(material(&first), material(&second));
    }
}
