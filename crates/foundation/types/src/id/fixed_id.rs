//! Fixed-size byte IDs (format spec section 4.1).
//!
//! An all-zero ID is never valid (FS-03). IDs that a backend stores in clear print as full
//! lowercase hex; the others never print in full, so logs cannot leak them.

use std::fmt;
use std::str::FromStr;

use crate::format_error::FormatError;
use crate::id::ParseIdError;
use crate::id::hex;

/// Defines one fixed-size ID newtype.
///
/// `clear` IDs are stored in clear on a backend: they implement `Display` and `FromStr` as
/// lowercase hex. `hidden` IDs are not, so their `Debug` shows only a 4-byte prefix.
macro_rules! fixed_id {
    ($(#[$doc:meta])* $name:ident, $len:literal, clear) => {
        fixed_id!(@common $(#[$doc])* $name, $len);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                hex::write_lower(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            /// Parses lowercase hex of full length. Uppercase is rejected (FS-92).
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                let bytes = hex::decode_lower::<$len>(text)?;
                Self::try_from_bytes(bytes).map_err(|_| ParseIdError::Zero)
            }
        }
    };
    ($(#[$doc:meta])* $name:ident, $len:literal, hidden) => {
        fixed_id!(@common $(#[$doc])* $name, $len);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(", stringify!($name))?;
                hex::write_lower(&self.0[..4], f)?;
                f.write_str("…)")
            }
        }
    };
    (@common $(#[$doc:meta])* $name:ident, $len:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Length of the ID in bytes.
            pub const LEN: usize = $len;

            /// Wraps raw bytes.
            ///
            /// # Errors
            ///
            /// [`FormatError::ZeroValue`] if every byte is zero (FS-03).
            pub fn try_from_bytes(bytes: [u8; $len]) -> Result<Self, FormatError> {
                if bytes == [0u8; $len] {
                    Err(FormatError::ZeroValue)
                } else {
                    Ok(Self(bytes))
                }
            }

            /// The raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl TryFrom<[u8; $len]> for $name {
            type Error = FormatError;

            fn try_from(bytes: [u8; $len]) -> Result<Self, Self::Error> {
                Self::try_from_bytes(bytes)
            }
        }
    };
}

fixed_id!(
    /// The vault ID: `H(hash/vault-id, master_pk ‖ vault_nonce)[..16]` (FS-02).
    VaultId, 16, clear
);
fixed_id!(
    /// The random nonce that goes into the vault ID.
    VaultNonce, 16, clear
);
fixed_id!(
    /// A random device ID, chosen at enrolment.
    DeviceId, 16, clear
);
fixed_id!(
    /// A random share-slot ID.
    SlotId, 16, clear
);
fixed_id!(
    /// A random share-set ID.
    ShareSetId, 16, clear
);
fixed_id!(
    /// The ID of a queue-job sender: a daemon component, or a device on the bus (format spec
    /// section 16).
    SenderId, 16, clear
);
fixed_id!(
    /// A shard ID: the BLAKE3 hash of the whole shard file, used as its name.
    ShardId, 32, clear
);
fixed_id!(
    /// A key ID: the hash of a public key, named in signed envelopes.
    KeyId, 32, clear
);
fixed_id!(
    /// A random object ID. Never stored in clear.
    ObjectId, 16, hidden
);
fixed_id!(
    /// A random DEK ID. Never stored in clear.
    DekId, 16, hidden
);
fixed_id!(
    /// A random pack ID. Never stored in clear.
    PackId, 16, hidden
);
fixed_id!(
    /// A blob ID: keyed per object for ordinary data, random otherwise. Never stored in clear,
    /// since equal IDs reveal equal content.
    BlobId, 32, hidden
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_is_rejected() {
        assert_eq!(
            VaultId::try_from_bytes([0; 16]),
            Err(FormatError::ZeroValue)
        );
        assert_eq!(ShardId::try_from([0; 32]), Err(FormatError::ZeroValue));
        assert_eq!(BlobId::try_from_bytes([0; 32]), Err(FormatError::ZeroValue));
    }

    #[test]
    fn one_non_zero_byte_is_enough() {
        let mut bytes = [0u8; 16];
        bytes[15] = 1;
        let id = DeviceId::try_from_bytes(bytes).expect("non-zero ID");
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn clear_ids_round_trip_as_lowercase_hex() {
        let id = SlotId::try_from_bytes([0xab; 16]).expect("non-zero ID");
        let text = id.to_string();
        assert_eq!(text, "ab".repeat(16));
        assert_eq!(text.parse::<SlotId>(), Ok(id));
        assert_eq!(format!("{id:?}"), format!("SlotId({text})"));
    }

    #[test]
    fn parse_rejects_non_canonical_text() {
        assert_eq!(
            "AB".repeat(16).parse::<SlotId>(),
            Err(ParseIdError::NotLowercaseHex)
        );
        assert_eq!("ab".repeat(15).parse::<SlotId>(), Err(ParseIdError::Length));
        assert_eq!("00".repeat(16).parse::<SlotId>(), Err(ParseIdError::Zero));
    }

    #[test]
    fn hidden_ids_debug_only_a_prefix() {
        let id = ObjectId::try_from_bytes([0xcd; 16]).expect("non-zero ID");
        assert_eq!(format!("{id:?}"), "ObjectId(cdcdcdcd…)");
        let id = BlobId::try_from_bytes([0xef; 32]).expect("non-zero ID");
        assert_eq!(format!("{id:?}"), "BlobId(efefefef…)");
    }
}
