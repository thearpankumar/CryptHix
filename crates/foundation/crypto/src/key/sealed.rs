//! The private supertrait behind [`KeyMaterial`](crate::key::KeyMaterial) and the outputs of
//! [`kdf`](crate::kdf::kdf).
//!
//! The module is private to the crate, so other crates cannot name [`Token`], and without a
//! `Token` they cannot call the methods that read or build key bytes, even through a generic
//! bound on a public subtrait.

use std::num::NonZeroU8;

/// Proof that the caller is inside this crate. The non-zero field makes it impossible to
/// conjure with `mem::zeroed`, which panics for a type that has no all-zero value.
#[derive(Clone, Copy, Debug)]
pub struct Token(#[expect(dead_code, reason = "only its non-zero niche matters")] NonZeroU8);

/// The token, for this crate's own calls.
pub(crate) const TOKEN: Token = Token(NonZeroU8::MIN);

/// Access to the 32 bytes of a key or derived value, for this crate only.
pub trait Sealed: Sized {
    /// Takes ownership of 32 bytes of key material.
    fn from_material(bytes: [u8; 32], token: Token) -> Self;

    /// The 32 bytes of key material.
    fn material(&self, token: Token) -> &[u8; 32];
}

/// The bytes of `key`.
pub(crate) fn material<K: Sealed>(key: &K) -> &[u8; 32] {
    key.material(TOKEN)
}

/// Builds a `K` from 32 bytes.
pub(crate) fn from_material<K: Sealed>(bytes: [u8; 32]) -> K {
    K::from_material(bytes, TOKEN)
}
