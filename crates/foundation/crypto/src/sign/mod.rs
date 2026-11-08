//! Ed25519 signatures over a labelled, context-bound input (FS-13, FS-14, M-37).
//!
//! ```
//! use crypthix_crypto::label::SigLabel;
//! use crypthix_crypto::sign::SigningKey;
//!
//! let signer = SigningKey::random()?;
//! let ctx = [0u8; 16];
//! let signature = signer.sign(SigLabel::Root, &ctx, b"root body")?;
//! let verifier = signer.verifying_key();
//! verifier.verify(SigLabel::Root, &ctx, b"root body", &signature)?;
//! assert!(verifier.verify(SigLabel::Config, &ctx, b"root body", &signature).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod sig_input;
mod signature;
mod signing_key;
mod verify_error;
mod verifying_key;

pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verify_error::VerifyError;
pub use verifying_key::VerifyingKey;
