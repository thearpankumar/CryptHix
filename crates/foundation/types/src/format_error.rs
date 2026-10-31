//! The format error type (format spec section 19).

use std::error::Error;
use std::fmt;

/// Defines `FormatError` with its stable names and descriptions from one table.
macro_rules! format_errors {
    ($($(#[$doc:meta])* $variant:ident => $description:literal,)+) => {
        /// A format error from the error table of the format spec (section 19).
        ///
        /// Every failure to read a stored structure maps to exactly one variant: the first failing
        /// check in the order the rules give (FS-93). [`FormatError::name`] is the `expect` value
        /// used by the test vectors. The spec's `Commitment` and `AeadTag` errors are private to
        /// `crypthix-crypto`, which reports both as [`FormatError::Decrypt`].
        #[non_exhaustive]
        #[must_use]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub enum FormatError {
            $($(#[$doc])* $variant,)+
        }

        impl FormatError {
            /// Every variant, in the order of the spec's error table.
            pub const ALL: &'static [FormatError] = &[$(FormatError::$variant,)+];

            /// The stable name of the error, as used in test vectors.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(FormatError::$variant => stringify!($variant),)+
                }
            }

            /// A fixed, one-line description of the error.
            #[must_use]
            pub const fn description(self) -> &'static str {
                match self {
                    $(FormatError::$variant => $description,)+
                }
            }
        }
    };
}

format_errors! {
    /// Not a CryptHix file (FS-06).
    Magic => "not a CryptHix file",
    /// Unknown, nested or private-use file type (FS-06).
    UnknownType => "unknown, nested or private-use file type",
    /// File name or path does not match the content (FS-06, FS-92).
    NameMismatch => "file name or path does not match the content",
    /// Non-zero preamble flags (FS-07).
    Flags => "non-zero preamble flags",
    /// Bytes past the declared length (FS-07).
    TrailingBytes => "bytes past the declared length",
    /// Input shorter than declared (FS-07).
    Truncated => "input shorter than declared",
    /// A size, count, depth or fan-out limit was exceeded (FS-07, FS-11).
    Limit => "size, count, depth or fan-out limit exceeded",
    /// CBOR not in deterministic form (FS-08).
    NonCanonical => "CBOR not in deterministic form",
    /// Wrong type, missing key, wrong size, bad enum, invalid text or misplaced null (FS-09, FS-10).
    Schema => "value does not match the schema",
    /// Unknown negative (critical) map key (FS-09, FS-20).
    UnknownCritical => "unknown critical map key",
    /// Unknown format version (FS-16).
    UnsupportedFormat => "unknown format version",
    /// Suite other than the pinned one (FS-05, FS-16).
    UnsupportedSuite => "unsupported suite",
    /// Unknown struct version (FS-19).
    UnsupportedStruct => "unknown struct version",
    /// Format, suite or minimum version lower than the signed state (FS-17, FS-18).
    Downgrade => "format, suite or minimum version lower than the signed state",
    /// Unknown incompat feature bit, or a write with an unknown `ro_compat` bit (FS-21).
    Feature => "unknown feature bit",
    /// Zero key, ID, hash or counter (FS-03, FS-04).
    ZeroValue => "zero key, ID, hash or counter",
    /// `vault_id` does not match `master_pk` (FS-02).
    VaultId => "vault ID does not match the master key",
    /// Key lookup missed (FS-30).
    MissingKey => "key lookup missed",
    /// Any failure of the committing AEAD, as seen outside `crypthix-crypto` (FS-28).
    Decrypt => "decryption failed",
    /// A blob, header, entry or signer does not match what refers to it.
    Binding => "content does not match its reference",
    /// Argon2id parameters too weak (FS-41).
    KdfBelowFloor => "passphrase KDF parameters below the floor",
    /// Argon2id parameters too costly (FS-41).
    KdfAboveCeiling => "passphrase KDF parameters above the ceiling",
    /// Signature or MAC invalid (FS-13, FS-14, FS-86).
    Signature => "signature or MAC invalid",
    /// Small-order, mixed-order or non-canonical public key (FS-14).
    WeakKey => "weak or non-canonical public key",
    /// Certificate missing, wrong vault, wrong capability or stale (FS-76, FS-77).
    CertChain => "certificate chain invalid",
    /// Signer not active in the device set (FS-77).
    Revoked => "signer revoked",
    /// Outside a validity window (FS-76, FS-83, FS-86).
    Expired => "outside the validity window",
    /// Merkle or tree commitment mismatch (FS-66, FS-72).
    Merkle => "Merkle or tree commitment mismatch",
    /// Chunk count or length mismatch (FS-67).
    ChunkList => "chunk count or length mismatch",
    /// Reserved byte, pad or trailing header bytes not zero; bad compression code (FS-54, FS-60).
    Padding => "padding or reserved bytes invalid",
    /// Decompressed size wrong or over the cap (FS-53).
    Decompress => "decompressed size wrong or over the cap",
    /// Pack or shard bounds or parameters inconsistent (FS-60, FS-62).
    Layout => "pack or shard layout inconsistent",
    /// Shard or pack hash mismatch (FS-63, FS-64).
    ShardHash => "shard or pack hash mismatch",
    /// Path breaks the normalisation rules (FS-71).
    Path => "path breaks the normalisation rules",
    /// A counter or chain went backwards.
    Rollback => "counter or chain went backwards",
    /// Two roots with the same sequence number (FS-80).
    Fork => "two roots with the same sequence number",
    /// Device state missing or invalid (FS-81).
    StateLost => "device state missing or invalid",
    /// Key file of a retired epoch (FS-47).
    Retired => "key file of a retired epoch",
    /// Bad share index or scalar (FS-43).
    ShareInvalid => "invalid share",
    /// Shares from different sets or versions (FS-43).
    ShareMix => "shares from different sets or versions",
    /// Recovered root does not match `root_commit` (FS-43).
    RootCommit => "recovered root does not match its commitment",
    /// Recovery text checksum wrong (FS-45).
    Checksum => "recovery text checksum wrong",
    /// Job for another vault or recipient (FS-86).
    Audience => "job for another vault or recipient",
    /// Job sequence number not above the last seen (FS-86).
    Replay => "job sequence number replayed",
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(FormatError::description(*self))
    }
}

impl Error for FormatError {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    const FORMAT_SPEC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../docs/format-spec.md"
    ));

    /// Error names from the table in format spec section 19, in order.
    fn spec_error_names() -> Vec<&'static str> {
        let start = FORMAT_SPEC
            .find("## 19. Errors")
            .expect("spec has section 19");
        let section = &FORMAT_SPEC[start..];
        let end = section
            .find("**FS-93.**")
            .expect("section 19 ends with FS-93");
        section[..end]
            .lines()
            .filter_map(|line| line.strip_prefix("| `"))
            .filter_map(|rest| rest.split_once('`'))
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn names_match_the_spec_table() {
        let spec: Vec<&str> = spec_error_names()
            .into_iter()
            .filter(|name| !matches!(*name, "Commitment" | "AeadTag"))
            .collect();
        let code: Vec<&str> = FormatError::ALL.iter().map(|error| error.name()).collect();
        assert_eq!(
            code, spec,
            "FormatError drifted from format spec section 19"
        );
    }

    #[test]
    fn names_are_unique() {
        let names: HashSet<&str> = FormatError::ALL.iter().map(|error| error.name()).collect();
        assert_eq!(names.len(), FormatError::ALL.len());
    }

    #[test]
    fn display_is_the_description() {
        assert_eq!(FormatError::Magic.to_string(), "not a CryptHix file");
        for error in FormatError::ALL {
            assert!(
                !FormatError::description(*error).is_empty(),
                "{} has no description",
                error.name()
            );
        }
    }
}
