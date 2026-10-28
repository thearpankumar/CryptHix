//! `backends.toml`: where the vault's stores live.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::cbor;
use crate::config::{ConfigError, ConfigErrorKind};
use crate::id::VaultId;

/// The parsed `config/backends.toml`.
///
/// # Examples
///
/// ```
/// use crypthix_types::config::{BackendsConfig, parse_toml};
///
/// let config: BackendsConfig = parse_toml(
///     "[local]\nstore_root = \"/var/lib/crypthix/00112233445566778899aabbccddeeff/store\"\n",
/// )?;
/// config.validate()?;
/// assert!(config.local().is_some());
/// # Ok::<(), crypthix_types::config::ConfigError>(())
/// ```
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendsConfig {
    local: Option<LocalBackendConfig>,
}

impl BackendsConfig {
    /// The local backend, if configured.
    #[must_use]
    pub fn local(&self) -> Option<&LocalBackendConfig> {
        self.local.as_ref()
    }

    /// Checks the rules that parsing cannot express.
    ///
    /// # Errors
    ///
    /// [`ConfigErrorKind::Invalid`] if a store root is not an absolute path in normal form.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(local) = &self.local {
            local.validate()?;
        }
        Ok(())
    }
}

/// The `[local]` table: a store on a local filesystem. Unix paths only for now.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBackendConfig {
    store_root: PathBuf,
}

impl LocalBackendConfig {
    /// The `store/` directory of the vault.
    #[must_use]
    pub fn store_root(&self) -> &Path {
        &self.store_root
    }

    /// Checks the store root: an absolute Unix path in normal form, without control or
    /// bidirectional characters (FS-10), ending in `<vault-id hex>/store` as laid out in FS-92. A wrong root such as
    /// `/` would be handed to the daemon's ownership and mode changes, so it is refused here.
    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = ConfigError::new(ConfigErrorKind::Invalid);
        let text = self.store_root.to_str().ok_or(invalid)?;
        if !text.starts_with('/') || cbor::check_text(text).is_err() {
            return Err(invalid);
        }
        // `Path::components` drops `.` segments silently, so split the text itself.
        let segments: Vec<&str> = text[1..].split('/').collect();
        if segments
            .iter()
            .any(|segment| matches!(*segment, "" | "." | ".."))
        {
            return Err(invalid);
        }
        match segments.as_slice() {
            [.., vault, "store"] if vault.parse::<VaultId>().is_ok() => Ok(()),
            _ => Err(invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::parse_toml;

    #[test]
    fn empty_file_has_no_backends() {
        let config: BackendsConfig = parse_toml("").expect("valid");
        assert_eq!(config.local(), None);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn unknown_keys_are_rejected_with_a_position() {
        let error =
            parse_toml::<BackendsConfig>("[local]\nstore_root = \"/s\"\nstore_rot = \"/t\"\n")
                .expect_err("unknown key");
        assert_eq!(error.kind(), ConfigErrorKind::UnknownField);
        assert_eq!(error.line(), Some(3));
        let error = parse_toml::<BackendsConfig>("[s3]\n").expect_err("unknown table");
        assert_eq!(error.kind(), ConfigErrorKind::UnknownField);
    }

    #[test]
    fn missing_and_invalid_values() {
        let error = parse_toml::<BackendsConfig>("[local]\n").expect_err("missing key");
        assert_eq!(error.kind(), ConfigErrorKind::MissingField);
        let error =
            parse_toml::<BackendsConfig>("[local]\nstore_root = 5\n").expect_err("wrong type");
        assert_eq!(error.kind(), ConfigErrorKind::InvalidValue);
        let error = parse_toml::<BackendsConfig>("[local\n").expect_err("bad syntax");
        assert_eq!(error.kind(), ConfigErrorKind::Syntax);
    }

    #[test]
    fn errors_never_quote_values() {
        let secret = "hunter2-secret-token";
        let text = format!("[local]\nstore_root = \"/s\"\npassword = \"{secret}\"\n");
        let error = parse_toml::<BackendsConfig>(&text).expect_err("unknown key");
        assert!(
            !error.to_string().contains(secret),
            "Display quotes no value"
        );
        assert!(
            !format!("{error:?}").contains(secret),
            "Debug quotes no value"
        );
        let text = format!("[local]\nstore_root = [\"{secret}\"]\n");
        let error = parse_toml::<BackendsConfig>(&text).expect_err("wrong type");
        assert!(
            !error.to_string().contains(secret),
            "type errors quote no value"
        );
    }

    #[test]
    fn store_root_must_be_a_vault_store_directory() {
        let vault = "00112233445566778899aabbccddeeff";
        let good = format!("/var/lib/crypthix/{vault}/store");
        let config: BackendsConfig =
            parse_toml(&format!("[local]\nstore_root = \"{good}\"\n")).expect("parses");
        assert_eq!(config.validate(), Ok(()));
        for path in [
            "relative/store".to_owned(),
            "/".to_owned(),
            "/store".to_owned(),
            format!("/var/lib/../{vault}/store"),
            format!("/var/./lib/{vault}/store"),
            format!("/var//lib/{vault}/store"),
            format!("/var/lib/{vault}/store/"),
            format!("/var/lib/{}/store", vault.to_uppercase()),
            format!("/var/lib/{vault}/stores"),
            format!("/var/a\\u0000b/{vault}/store"),
            format!("/var/\\u202Eb/{vault}/store"),
        ] {
            let config: BackendsConfig =
                parse_toml(&format!("[local]\nstore_root = \"{path}\"\n")).expect("parses");
            assert_eq!(
                config.validate().map_err(|error| error.kind()),
                Err(ConfigErrorKind::Invalid),
                "{path}"
            );
        }
    }
}
