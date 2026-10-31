//! Argon2id for passphrase share slots (FS-41, M-10).

mod derive;
mod derive_error;
mod kdf_params;

pub use derive::derive;
pub use derive_error::DeriveError;
pub use kdf_params::KdfParams;
