//! Randomness straight from the kernel (FS-01, M-36).
//!
//! Every key, salt, random ID and the randomness of every hedged nonce comes from `getrandom(2)`. There is no user-space RNG
//! that a fork could duplicate. The kernel reseeds after a VM restore only when the hypervisor
//! exposes a VM generation ID (`vmgenid`), so no nonce uses this randomness directly: every
//! nonce is hedged with the key, AAD and plaintext (FS-29).

mod fill;
mod random_error;

pub use fill::{bytes, fill};
pub use random_error::RandomError;
