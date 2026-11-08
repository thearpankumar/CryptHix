//! The only crate that uses cryptography libraries (backlog rule 3).
//!
//! It wraps audited crates for suite `0x0001` of the format spec (section 4.2):
//!
//! - [`cx_aead`]: XChaCha20-Poly1305 inside the committing CX-AEAD (section 7.2, M-9);
//! - [`kdf`]: HKDF-SHA-256 under the label registry of section 7.1 (M-37);
//! - [`hash`] and [`mac`]: BLAKE3 as `H`, `MAC` and the gear-table XOF;
//! - [`sign`]: Ed25519 with strict, canonical verification (FS-13, FS-14);
//! - [`argon2id`]: Argon2id with the bounds of FS-41;
//! - [`random`]: keys, IDs and the randomness of every hedged nonce straight from the
//!   kernel's `getrandom` (FS-01, FS-29, M-36);
//! - [`secure_mem`]: the protected memory every key and plaintext buffer lives in (O1, T-31).
//!
//! Keys are zeroizing types from [`key`], one per primitive, and never cross a crate API as
//! bytes (rule 9). Each lives in a slot of protected memory: `memfd_secret` pages where the
//! kernel has them, else `mlock`ed or dump-excluded pages, and the heap only where the app's
//! minimum allows it. Opened plaintext is a [`SecretBuf`](secure_mem::SecretBuf), locked when
//! `RLIMIT_MEMLOCK` allows and otherwise dump-excluded; off Linux both are plain heap memory,
//! wiped on free. An app calls [`secure_mem::init`] once at startup with the weakest protection
//! it accepts, and shows what it got with [`secure_mem::status`].
//!
//! Each failure has its own error type:
//! [`FormatError`](crypthix_types::format_error::FormatError) for input that does not parse,
//! verify or open, where a CX-AEAD failure is the one opaque `Decrypt` (FS-28);
//! [`KeyError`](key::KeyError) when no key is made; [`MemError`](secure_mem::MemError) when no
//! protected memory is had; [`SealError`](cx_aead::SealError) when a seal fails;
//! [`DeriveError`](argon2id::DeriveError) when Argon2id fails; and
//! [`RandomError`](random::RandomError) when the kernel gives no randomness.
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
//! let wrapping_key = kdf::kdf(&kek, None, SealKeyLabel::DekWrap, &context)?;
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
pub mod secure_mem;
pub mod sign;
#[cfg(feature = "test-rng")]
pub mod test_rng;
