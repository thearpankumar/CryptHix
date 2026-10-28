//! Store names and prefixes (format spec section 18).

#[expect(
    clippy::module_inception,
    reason = "files are named after their main item"
)]
mod store_key;
mod store_prefix;

pub use store_key::StoreKey;
pub use store_prefix::StorePrefix;
