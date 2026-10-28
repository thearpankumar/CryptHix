//! Config errors.

use std::error::Error;
use std::fmt;

/// What kind of config error occurred.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ConfigErrorKind {
    /// The text is not valid TOML.
    Syntax,
    /// A key the schema does not know. Configs reject unknown keys, so a typo is never ignored.
    UnknownField,
    /// A required key is missing.
    MissingField,
    /// A value has the wrong type or is out of range.
    InvalidValue,
    /// The config parsed but breaks a rule checked after parsing.
    Invalid,
}

/// A config file that could not be loaded.
///
/// It holds a kind and a position only. The parser's message is dropped, because it can quote
/// values from the file, and config files may hold credentials.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ConfigError {
    kind: ConfigErrorKind,
    line: Option<u32>,
    column: Option<u32>,
}

impl ConfigError {
    /// An error without a position.
    pub const fn new(kind: ConfigErrorKind) -> Self {
        Self {
            kind,
            line: None,
            column: None,
        }
    }

    /// An error at a 1-based line and column.
    pub const fn at(kind: ConfigErrorKind, line: u32, column: u32) -> Self {
        Self {
            kind,
            line: Some(line),
            column: Some(column),
        }
    }

    /// The kind of error.
    #[must_use]
    pub const fn kind(&self) -> ConfigErrorKind {
        self.kind
    }

    /// The 1-based line, if known.
    #[must_use]
    pub const fn line(&self) -> Option<u32> {
        self.line
    }

    /// The 1-based column, if known.
    #[must_use]
    pub const fn column(&self) -> Option<u32> {
        self.column
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            ConfigErrorKind::Syntax => "config syntax error",
            ConfigErrorKind::UnknownField => "unknown config key",
            ConfigErrorKind::MissingField => "missing config key",
            ConfigErrorKind::InvalidValue => "invalid config value",
            ConfigErrorKind::Invalid => "config breaks a rule",
        })?;
        if let (Some(line), Some(column)) = (self.line, self.column) {
            write!(f, " at line {line}, column {column}")?;
        }
        Ok(())
    }
}

impl Error for ConfigError {}
