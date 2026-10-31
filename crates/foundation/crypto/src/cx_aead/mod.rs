//! CX-AEAD: XChaCha20-Poly1305 that commits to its key, nonce and AAD (format spec 7.2, M-9).
//!
//! ```text
//! nonce [24] ‖ commitment C [32] ‖ ciphertext [len(pt)] ‖ tag [16]     (72 bytes of overhead)
//! ```
//!
//! [`open`] recomputes `C` and compares it in constant time before it checks the tag (FS-28).
//! Callers see one opaque [`FormatError::Decrypt`](crypthix_types::format_error::FormatError)
//! for any failure, so there is no oracle; the two inner causes are visible only with the
//! `vectors` feature, for TV-05.
//!
//! ```
//! use crypthix_crypto::aad::Aad;
//! use crypthix_crypto::cx_aead::{self, NonceKind};
//! use crypthix_crypto::key::SealKey;
//! use crypthix_crypto::label::AadLabel;
//!
//! let key = SealKey::random()?;
//! let aad = Aad::new(AadLabel::Manifest).field(&[1u8; 16]);
//! let sealed = cx_aead::seal(&key, &aad, b"manifest body", NonceKind::Hedged)?;
//! assert_eq!(sealed.len(), cx_aead::OVERHEAD + 13);
//! assert_eq!(cx_aead::open(&key, &aad, &sealed)?.as_slice(), b"manifest body");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod layout;
mod nonce;
mod nonce_kind;
mod open;
mod open_error;
mod seal;
mod seal_error;

pub use layout::WRAPPED_KEY_LEN;
pub use layout::{COMMITMENT_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, OVERHEAD, TAG_LEN};
#[cfg(feature = "vectors")]
pub use nonce::{hedged_nonce, synthetic_nonce};
pub use nonce_kind::NonceKind;
#[cfg(feature = "vectors")]
pub use open::open_detailed;
pub use open::{open, open_key};
#[cfg(feature = "vectors")]
pub use open_error::OpenError;
#[cfg(feature = "vectors")]
pub use seal::seal_with_nonce;
pub use seal::{seal, seal_key};
pub use seal_error::SealError;
