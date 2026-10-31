//! Ed25519 signatures over a labelled, context-bound input (FS-13, FS-14, M-37).
//!
//! ```
//! use crypthix_crypto::label::SigLabel;
//! use crypthix_crypto::sign::SigningKey;
//!
//! let signer = SigningKey::random()?;
//! let ctx = [0u8; 16];
//! let signature = signer.sign(SigLabel::Root, &ctx, b"root body");
//! let verifier = signer.verifying_key();
//! assert!(verifier.verify(SigLabel::Root, &ctx, b"root body", &signature).is_ok());
//! assert!(verifier.verify(SigLabel::Config, &ctx, b"root body", &signature).is_err());
//! # Ok::<(), crypthix_crypto::random::RandomError>(())
//! ```

mod sig_input;
mod signature;
mod signing_key;
mod verifying_key;

pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verifying_key::VerifyingKey;
