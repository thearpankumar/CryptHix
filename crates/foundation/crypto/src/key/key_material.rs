//! The trait of every key that can be wrapped with CX-AEAD.

use crate::key::sealed::Sealed;

/// A secret key that [`cx_aead::seal_key`](crate::cx_aead::seal_key) can wrap and
/// [`cx_aead::open_key`](crate::cx_aead::open_key) can unwrap, so key bytes never cross a crate
/// API (backlog rule 9).
///
/// The trait is sealed, and so are the methods that reach the key bytes: other crates can name
/// the trait in a bound but cannot read or build a key through it.
///
/// ```compile_fail
/// use crypthix_crypto::key::KeyMaterial;
///
/// fn leak<K: KeyMaterial>(key: &K) -> [u8; 32] {
///     *key.material()
/// }
/// ```
pub trait KeyMaterial: Sealed {}
