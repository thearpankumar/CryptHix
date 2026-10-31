//! The only crate that uses cryptography libraries (backlog rule 3).
//!
//! It wraps audited crates for suite `0x0001` of the format spec (section 4.2):
//!
//! - [`cx_aead`]: XChaCha20-Poly1305 inside the committing CX-AEAD (section 7.2, M-9);
//! - [`kdf`]: HKDF-SHA-256 under the label registry of section 7.1 (M-37);
//! - [`hash`] and [`mac`]: BLAKE3 as `H`, `MAC` and the gear-table XOF;
//! - [`sign`]: Ed25519 with strict, canonical verification (FS-13, FS-14);
//! - [`argon2id`]: Argon2id with the bounds of FS-41;
//! - [`random`]: keys, IDs and the randomness of every hedged nonce straight from the kernel's `getrandom`
//!   (FS-01, FS-29, M-36).
//!
//! Keys are zeroizing types from [`key`], one per primitive, and never cross a crate API as
//! bytes (rule 9). Failures are [`FormatError`](crypthix_types::format_error::FormatError)s; a
//! CX-AEAD failure is the one opaque `Decrypt` (FS-28).
//!
//! ```
//! use crypthix_crypto::aad::Aad;
//! use crypthix_crypto::cx_aead;
//! use crypthix_crypto::kdf::{self, KdfContext};
//! use crypthix_crypto::key::KdfKey;
//! use crypthix_crypto::label::{AadLabel, SealKeyLabel};
//!
//! // Wrap a fresh DEK under an epoch's DEK-wrapping key (section 9.7).
//! let kek = KdfKey::random()?;
//! let vault_id = [1u8; 16];
//! let context = KdfContext::new().field(&vault_id).u32be(1);
//! let wrapping_key = kdf::kdf(&kek, None, SealKeyLabel::DekWrap, &context);
//! let aad = Aad::new(AadLabel::DekWrap).field(&vault_id).u32be(1);
//! let dek = KdfKey::random()?;
//! let wrap = cx_aead::seal_key(&wrapping_key, &aad, &dek)?;
//! let unwrapped: KdfKey = cx_aead::open_key(&wrapping_key, &aad, &wrap)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Features (never enabled by a release build, FS-01):
//! - `test-rng`: the seeded stream of the vector generator (FS-94);
//! - `vectors`: the inner CX-AEAD failure names and raw entry points for the vector runners;
//!   it can build keys from chosen bytes and seal with a chosen nonce.

pub mod aad;
pub mod argon2id;
pub mod cx_aead;
pub mod hash;
pub mod kdf;
pub mod key;
pub mod label;
pub mod mac;
pub mod random;
pub mod sign;
#[cfg(feature = "test-rng")]
pub mod test_rng;
