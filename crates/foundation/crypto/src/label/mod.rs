//! The label registry of format spec section 7.1.
//!
//! Every label has the form `crypthix/v0/<class>/<purpose>` and serves exactly one purpose
//! (FS-25). Each class is its own enum, so a KDF label cannot be passed where a hash label is
//! expected, and the KDF labels are also split by the type they derive.

mod aad_label;
pub(crate) mod derive_label;
mod hash_label;
mod kdf_label;
pub(crate) mod labels;
mod sig_label;
mod typed_labels;

pub use aad_label::AadLabel;
pub use derive_label::DeriveLabel;
pub use hash_label::HashLabel;
pub use kdf_label::KdfLabel;
pub use sig_label::SigLabel;
pub use typed_labels::XofKeyLabel;
pub use typed_labels::{CommitLabel, KdfKeyLabel, MacKeyLabel, SealKeyLabel, ShardNonceKeyLabel};
