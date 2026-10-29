//! Config loading never panics, and its errors carry nothing from the file.

use crypthix_types::config::{BackendsConfig, ConfigError, parse_toml};

/// The only texts a [`ConfigError`] may start with.
const MESSAGES: [&str; 5] = [
    "config syntax error",
    "unknown config key",
    "missing config key",
    "invalid config value",
    "config breaks a rule",
];

/// Loads `data` as `backends.toml` when it is UTF-8, then validates it.
///
/// # Panics
///
/// If an error's position lies outside the input, or its text is anything but a fixed message
/// and a position: config files may hold credentials, so no input may reach logs.
pub fn config_toml(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match parse_toml::<BackendsConfig>(text) {
        Ok(config) => {
            if let Err(error) = config.validate() {
                check_error(&error, text);
            }
        }
        Err(error) => check_error(&error, text),
    }
}

fn check_error(error: &ConfigError, text: &str) {
    let lines = text.split('\n').count();
    if let Some(line) = error.line() {
        assert!(
            line >= 1 && line as usize <= lines + 1,
            "line {line} of {lines}"
        );
    }
    if let Some(column) = error.column() {
        assert!(
            column >= 1 && column as usize <= text.len() + 1,
            "column {column}"
        );
    }
    let shown = error.to_string();
    let rest = MESSAGES
        .iter()
        .find_map(|message| shown.strip_prefix(message))
        .unwrap_or_else(|| panic!("unexpected error text: {shown}"));
    let position = rest
        .strip_prefix(" at line ")
        .map(|rest| rest.replacen(", column ", "", 1));
    assert!(
        rest.is_empty()
            || position.is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_digit())),
        "error text carries more than a position: {shown}"
    );
}
