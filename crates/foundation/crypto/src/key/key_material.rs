//! The trait of every key that can be wrapped with CX-AEAD.

use crate::key::sealed::Sealed;

/// A secret key that [`cx_aead::seal_key`](crate::cx_aead::seal_key) can wrap and
/// [`cx_aead::open_key`](crate::cx_aead::open_key) can unwrap, so key bytes never cross a crate
/// API (backlog rule 9).
///
/// The trait is sealed, and so are the methods that reach the key bytes: other crates can name
/// the trait in a bound, and even call its supertrait's methods through it, but each of those
/// takes a token only this crate can name, so they cannot read or build a key through it.
///
/// A bound on the trait reaches the sealed methods, but the token they take cannot be named
/// outside this crate, and no safe public way builds one, not even by inference:
///
/// ```compile_fail,E0277
/// use crypthix_crypto::key::KeyMaterial;
///
/// fn leak<K: KeyMaterial>(key: &K) -> [u8; 32] {
///     *key.material(Default::default())
/// }
/// ```
pub trait KeyMaterial: Sealed {}
