//! Strict TOML parsing.

use std::ops::Range;

use serde::de::DeserializeOwned;
use toml::Table;

use crate::config::{ConfigError, ConfigErrorKind};

/// Parses a config file's text into `T`.
///
/// Config structs reject unknown keys (`#[serde(deny_unknown_fields)]`). This function does no
/// file I/O: the daemon reads the file, since only it may touch its config directory (M-7).
///
/// # Errors
///
/// A [`ConfigError`] with the kind and position of the first problem.
pub fn parse_toml<T: DeserializeOwned>(text: &str) -> Result<T, ConfigError> {
    // Two passes: any failure to parse plain TOML is a syntax error, so only schema errors from
    // the second pass are classified by their message.
    if let Err(error) = text.parse::<Table>() {
        return Err(located(text, ConfigErrorKind::Syntax, error.span()));
    }
    toml::from_str(text).map_err(|error| located(text, classify(error.message()), error.span()))
}

fn located(text: &str, kind: ConfigErrorKind, span: Option<Range<usize>>) -> ConfigError {
    match span {
        Some(span) => {
            let (line, column) = position(text, span.start);
            ConfigError::at(kind, line, column)
        }
        None => ConfigError::new(kind),
    }
}

/// The kind of a serde error, from the fixed prefix of its message. The prefixes come from
/// serde's `de::Error` constructors; the tests pin them for the toml version in `Cargo.lock`.
fn classify(message: &str) -> ConfigErrorKind {
    if message.starts_with("unknown field") {
        ConfigErrorKind::UnknownField
    } else if message.starts_with("missing field") {
        ConfigErrorKind::MissingField
    } else if message.starts_with("invalid") || message.starts_with("unknown variant") {
        ConfigErrorKind::InvalidValue
    } else {
        ConfigErrorKind::Syntax
    }
}

/// The 1-based line and column of a byte offset.
fn position(text: &str, offset: usize) -> (u32, u32) {
    let before = text.get(..offset).unwrap_or(text);
    let line = before.matches('\n').count() + 1;
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |last| last.chars().count())
        + 1;
    (
        u32::try_from(line).unwrap_or(u32::MAX),
        u32::try_from(column).unwrap_or(u32::MAX),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[expect(dead_code, reason = "fields are only parsed")]
    struct Sample {
        name: String,
        count: u32,
    }

    fn kind(text: &str) -> ConfigErrorKind {
        parse_toml::<Sample>(text)
            .expect_err("invalid config")
            .kind()
    }

    #[test]
    fn lexer_errors_are_syntax_errors() {
        // Messages of these start with "invalid", which must not make them InvalidValue.
        assert_eq!(
            kind("name = \"a\\u0000\"\ncount = 1\nx = \"\u{0}\"\n"),
            ConfigErrorKind::Syntax
        );
        assert_eq!(kind("name = '''abc\ncount = 1\n"), ConfigErrorKind::Syntax);
        assert_eq!(
            kind("name = \"\\uD800\"\ncount = 1\n"),
            ConfigErrorKind::Syntax
        );
        assert_eq!(
            kind("name = \"a\"\nname = \"b\"\ncount = 1\n"),
            ConfigErrorKind::Syntax
        );
        assert_eq!(kind("[name\n"), ConfigErrorKind::Syntax);
    }

    #[test]
    fn schema_errors_are_classified() {
        assert_eq!(
            kind("name = \"a\"\ncount = 1\nextra = 2\n"),
            ConfigErrorKind::UnknownField
        );
        assert_eq!(kind("name = \"a\"\n"), ConfigErrorKind::MissingField);
        assert_eq!(
            kind("name = \"a\"\ncount = \"many\"\n"),
            ConfigErrorKind::InvalidValue
        );
        assert_eq!(
            kind("name = \"a\"\ncount = -1\n"),
            ConfigErrorKind::InvalidValue
        );
    }

    #[test]
    fn positions_are_one_based() {
        let error =
            parse_toml::<Sample>("name = \"a\"\ncount = 1\nextra = 2\n").expect_err("unknown");
        assert_eq!((error.line(), error.column()), (Some(3), Some(1)));
    }
}
