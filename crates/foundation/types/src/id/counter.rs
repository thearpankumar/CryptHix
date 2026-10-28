//! Counters that start at 1 and never wrap (FS-04).

use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use std::str::FromStr;

use crate::format_error::FormatError;
use crate::id::ParseIdError;

/// Defines one counter newtype over a non-zero integer.
macro_rules! counter {
    ($(#[$doc:meta])* $name:ident, $int:ty, $nonzero:ty) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name($nonzero);

        impl $name {
            /// The first value, 1.
            pub const FIRST: Self = Self(<$nonzero>::MIN);

            /// Wraps a raw value.
            ///
            /// # Errors
            ///
            /// [`FormatError::ZeroValue`] for 0 (FS-04).
            pub const fn try_new(value: $int) -> Result<Self, FormatError> {
                match <$nonzero>::new(value) {
                    Some(value) => Ok(Self(value)),
                    None => Err(FormatError::ZeroValue),
                }
            }

            /// The raw value.
            #[must_use]
            pub const fn get(self) -> $int {
                self.0.get()
            }

            /// The next value, or `None` at the maximum. Counters never wrap (FS-04).
            #[must_use]
            pub const fn checked_next(self) -> Option<Self> {
                match self.0.checked_add(1) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }
        }

        impl TryFrom<$int> for $name {
            type Error = FormatError;

            fn try_from(value: $int) -> Result<Self, Self::Error> {
                Self::try_new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            /// Parses decimal digits without sign or leading zeros (FS-92).
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                let value: $int = parse_decimal(text)?.try_into().map_err(|_| ParseIdError::Overflow)?;
                Self::try_new(value).map_err(|_| ParseIdError::Zero)
            }
        }
    };
}

/// Parses canonical decimal text: digits only, no leading zero.
pub(crate) fn parse_decimal(text: &str) -> Result<u64, ParseIdError> {
    if text.is_empty() {
        return Err(ParseIdError::Length);
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ParseIdError::NotDecimal);
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(ParseIdError::LeadingZero);
    }
    let mut value: u64 = 0;
    for digit in text.bytes() {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or(ParseIdError::Overflow)?;
    }
    Ok(value)
}

counter!(
    /// A key epoch.
    Epoch, u32, NonZeroU32
);
counter!(
    /// A keyring generation.
    KeyringGen, u32, NonZeroU32
);
counter!(
    /// The version of a share set.
    ShareSetVersion, u32, NonZeroU32
);
counter!(
    /// The sequence number of a vault root, the anti-rollback counter.
    RootSeq, u64, NonZeroU64
);
counter!(
    /// The sequence number of the vault config.
    ConfigSeq, u64, NonZeroU64
);
counter!(
    /// The sequence number of a device set.
    DeviceSetSeq, u64, NonZeroU64
);
counter!(
    /// The sequence number of a device certificate.
    CertSeq, u64, NonZeroU64
);
counter!(
    /// The version of an object.
    ObjectVersion, u64, NonZeroU64
);
counter!(
    /// The sequence number of a genome-log entry.
    LogSeq, u64, NonZeroU64
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_rejected() {
        assert_eq!(RootSeq::try_new(0), Err(FormatError::ZeroValue));
        assert_eq!(Epoch::try_from(0), Err(FormatError::ZeroValue));
    }

    #[test]
    fn starts_at_one_and_never_wraps() {
        assert_eq!(Epoch::FIRST.get(), 1);
        assert_eq!(Epoch::FIRST.checked_next().map(Epoch::get), Some(2));
        let last = Epoch::try_new(u32::MAX).expect("non-zero");
        assert_eq!(last.checked_next(), None);
        let last = RootSeq::try_new(u64::MAX).expect("non-zero");
        assert_eq!(last.checked_next(), None);
    }

    #[test]
    fn decimal_round_trip() {
        let seq = RootSeq::try_new(1234).expect("non-zero");
        assert_eq!(seq.to_string(), "1234");
        assert_eq!("1234".parse::<RootSeq>(), Ok(seq));
        assert_eq!(format!("{seq:?}"), "RootSeq(1234)");
    }

    #[test]
    fn parse_rejects_non_canonical_text() {
        assert_eq!("".parse::<Epoch>(), Err(ParseIdError::Length));
        assert_eq!("01".parse::<Epoch>(), Err(ParseIdError::LeadingZero));
        assert_eq!("0".parse::<Epoch>(), Err(ParseIdError::Zero));
        assert_eq!("+1".parse::<Epoch>(), Err(ParseIdError::NotDecimal));
        assert_eq!("4294967296".parse::<Epoch>(), Err(ParseIdError::Overflow));
        assert_eq!(
            "18446744073709551616".parse::<RootSeq>(),
            Err(ParseIdError::Overflow)
        );
    }
}
