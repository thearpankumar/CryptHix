//! `KDF(ikm, salt, label, ctx)`: HKDF-SHA-256, the only KDF of format 0 (FS-26).
//!
//! ```
//! use crypthix_crypto::kdf::{self, KdfContext};
//! use crypthix_crypto::key::{KdfKey, SealKey};
//! use crypthix_crypto::label::SealKeyLabel;
//!
//! let kek = KdfKey::random()?;
//! let context = KdfContext::new().field(&[7u8; 16]).u32be(1);
//! let dek_wrap: SealKey = kdf::kdf(&kek, None, SealKeyLabel::DekWrap, &context);
//! # Ok::<(), crypthix_crypto::random::RandomError>(())
//! ```
//!
//! The label fixes the output type, so a label cannot derive a key of another type:
//!
//! ```compile_fail
//! use crypthix_crypto::kdf::{self, KdfContext};
//! use crypthix_crypto::key::{KdfKey, MacKey};
//! use crypthix_crypto::label::SealKeyLabel;
//!
//! let kek = KdfKey::random().unwrap();
//! let wrong: MacKey = kdf::kdf(&kek, None, SealKeyLabel::DekWrap, &KdfContext::new());
//! ```

mod derive;
mod kdf_context;

pub(crate) use derive::expand;
pub use derive::kdf;
pub use kdf_context::KdfContext;
