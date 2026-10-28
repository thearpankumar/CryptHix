//! Config loading: strict TOML into typed structs.
//!
//! Only `backends.toml` is defined so far; `policy.toml` and `guard.toml` come with the features
//! that use them. File I/O stays in the daemon.

mod backends_config;
mod config_error;
mod parse_toml;

pub use backends_config::{BackendsConfig, LocalBackendConfig};
pub use config_error::{ConfigError, ConfigErrorKind};
pub use parse_toml::parse_toml;
