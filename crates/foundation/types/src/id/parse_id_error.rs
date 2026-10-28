//! The error returned when an ID or counter is parsed from text.

use std::error::Error;
use std::fmt;

/// Why an ID or counter could not be parsed from its canonical text form.
///
/// Canonical forms are lowercase hex of full length for IDs and decimal without leading zeros
/// for counters (FS-92).
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ParseIdError {
    /// The text has the wrong number of characters.
    Length,
    /// The text contains something other than lowercase hex digits.
    NotLowercaseHex,
    /// The text contains something other than decimal digits.
    NotDecimal,
    /// A decimal counter has a leading zero.
    LeadingZero,
    /// The value is zero, which is never valid (FS-03, FS-04).
    Zero,
    /// The decimal value does not fit the counter type.
    Overflow,
}

impl fmt::Display for ParseIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParseIdError::Length => "wrong length",
            ParseIdError::NotLowercaseHex => "not lowercase hex",
            ParseIdError::NotDecimal => "not a decimal number",
            ParseIdError::LeadingZero => "leading zero",
            ParseIdError::Zero => "zero value",
            ParseIdError::Overflow => "value too large",
        })
    }
}

impl Error for ParseIdError {}
