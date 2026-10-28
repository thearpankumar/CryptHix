//! Names of files in a store (format spec section 18, FS-92).

use std::fmt;
use std::str::FromStr;

use crate::format_error::FormatError;
use crate::id::hex;
use crate::id::{ConfigSeq, DeviceId, DeviceSetSeq, Epoch, KeyringGen, RootSeq, ShardId, SlotId};
use crate::preamble::Preamble;
use crate::registry::FileType;

/// The name of a file in a store, relative to `store/`.
///
/// Every backend holds exactly these names. The value in a name must equal the value in the
/// file; the structure parsers check that (`NameMismatch`).
///
/// # Examples
///
/// ```
/// use crypthix_types::id::RootSeq;
/// use crypthix_types::store_key::StoreKey;
///
/// let key = StoreKey::Root(RootSeq::try_new(42)?);
/// assert_eq!(key.to_string(), "roots/00000000000000000042.chx");
/// assert_eq!(StoreKey::parse("roots/00000000000000000042.chx")?, Some(key));
/// assert_eq!(StoreKey::parse("notes.txt")?, None);
/// # Ok::<(), crypthix_types::format_error::FormatError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum StoreKey {
    /// `configs/<config_seq>.chx`. Configs are immutable, like everything a root commits to.
    Config(ConfigSeq),
    /// `roots/<root_seq, 20 digits>.chx`.
    Root(RootSeq),
    /// `keys/slot-<slot_id hex>.chx`.
    Slot(SlotId),
    /// `keys/keyring-<gen>.chx`.
    Keyring(KeyringGen),
    /// `keys/epoch-<epoch>.chx`.
    Epoch(Epoch),
    /// `keys/vault-sign.chx`.
    VaultSigningKey,
    /// `keys/log-key.chx`. Reserved for Phase 3.
    LogKey,
    /// `devices/<device_id hex>.chx`.
    DeviceCertificate(DeviceId),
    /// `devices/set-<device_set_seq>.chx`.
    DeviceSet(DeviceSetSeq),
    /// `shards/<2 hex>/<64 hex>.chx`.
    Shard(ShardId),
}

const EXTENSION: &str = ".chx";

impl StoreKey {
    /// Parses a store-relative name.
    ///
    /// A name that fits no pattern is `Ok(None)`: readers ignore it (FS-92). A name that fits a
    /// pattern but is not canonical (uppercase hex, a leading zero, a root number that is not
    /// 20 digits, a zero value, a fan-out directory that does not match) is `NameMismatch`.
    ///
    /// # Errors
    ///
    /// [`FormatError::NameMismatch`] for a non-canonical name of a known pattern.
    pub fn parse(name: &str) -> Result<Option<Self>, FormatError> {
        let parts: Vec<&str> = name.split('/').collect();
        let key = match parts.as_slice() {
            ["configs", file] => stem(file)
                .map(|number| decimal(number).map(|number| number.map(StoreKey::Config)))
                .transpose()?
                .flatten(),
            ["roots", file] => stem(file).map(root).transpose()?.flatten(),
            ["keys", file] => stem(file).map(key_file).transpose()?.flatten(),
            ["devices", file] => stem(file).map(device_file).transpose()?.flatten(),
            ["shards", fanout, file] => stem(file)
                .map(|stem| shard(fanout, stem))
                .transpose()?
                .flatten(),
            _ => None,
        };
        Ok(key)
    }

    /// The file type a file under this name must have.
    #[must_use]
    pub const fn file_type(&self) -> FileType {
        match self {
            StoreKey::Config(_) => FileType::VaultConfig,
            StoreKey::Root(_) => FileType::VaultRoot,
            StoreKey::Slot(_) => FileType::ShareSlot,
            StoreKey::Keyring(_) => FileType::Keyring,
            StoreKey::Epoch(_) => FileType::EpochKey,
            StoreKey::VaultSigningKey => FileType::VaultSigningKey,
            StoreKey::LogKey => FileType::LogKey,
            StoreKey::DeviceCertificate(_) => FileType::DeviceCertificate,
            StoreKey::DeviceSet(_) => FileType::DeviceSet,
            StoreKey::Shard(_) => FileType::Shard,
        }
    }

    /// Checks that a file's type matches its name (FS-06).
    ///
    /// # Errors
    ///
    /// [`FormatError::NameMismatch`] if the types differ.
    pub fn check_type(&self, file_type: FileType) -> Result<(), FormatError> {
        if self.file_type() == file_type {
            Ok(())
        } else {
            Err(FormatError::NameMismatch)
        }
    }

    /// The largest file that may be stored under this name: preamble plus the type's cap.
    #[must_use]
    pub const fn max_file_len(&self) -> u64 {
        Preamble::LEN as u64 + self.file_type().max_body_len() as u64
    }
}

impl fmt::Display for StoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreKey::Config(seq) => write!(f, "configs/{seq}{EXTENSION}"),
            StoreKey::Root(seq) => write!(f, "roots/{:020}{EXTENSION}", seq.get()),
            StoreKey::Slot(id) => write!(f, "keys/slot-{id}{EXTENSION}"),
            StoreKey::Keyring(generation) => write!(f, "keys/keyring-{generation}{EXTENSION}"),
            StoreKey::Epoch(epoch) => write!(f, "keys/epoch-{epoch}{EXTENSION}"),
            StoreKey::VaultSigningKey => f.write_str("keys/vault-sign.chx"),
            StoreKey::LogKey => f.write_str("keys/log-key.chx"),
            StoreKey::DeviceCertificate(id) => write!(f, "devices/{id}{EXTENSION}"),
            StoreKey::DeviceSet(seq) => write!(f, "devices/set-{seq}{EXTENSION}"),
            StoreKey::Shard(id) => {
                f.write_str("shards/")?;
                hex::write_lower(&id.as_bytes()[..1], f)?;
                write!(f, "/{id}{EXTENSION}")
            }
        }
    }
}

/// The name without its `.chx` extension, if it has one.
fn stem(file: &str) -> Option<&str> {
    file.strip_suffix(EXTENSION)
}

fn root(stem: &str) -> Result<Option<StoreKey>, FormatError> {
    if stem.is_empty() || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    if stem.len() != 20 {
        return Err(FormatError::NameMismatch);
    }
    // Twenty digits may exceed u64; the zero padding is the one allowed leading zero form.
    let digits = stem.trim_start_matches('0');
    let value = crate::id::parse_decimal(digits).map_err(|_| FormatError::NameMismatch)?;
    let seq = RootSeq::try_new(value).map_err(|_| FormatError::NameMismatch)?;
    Ok(Some(StoreKey::Root(seq)))
}

fn key_file(stem: &str) -> Result<Option<StoreKey>, FormatError> {
    Ok(Some(match stem {
        "vault-sign" => StoreKey::VaultSigningKey,
        "log-key" => StoreKey::LogKey,
        _ => {
            if let Some(id) = stem.strip_prefix("slot-") {
                return hex_id(id).map(|id| id.map(StoreKey::Slot));
            }
            if let Some(number) = stem.strip_prefix("keyring-") {
                return decimal(number).map(|number| number.map(StoreKey::Keyring));
            }
            if let Some(number) = stem.strip_prefix("epoch-") {
                return decimal(number).map(|number| number.map(StoreKey::Epoch));
            }
            return Ok(None);
        }
    }))
}

fn device_file(stem: &str) -> Result<Option<StoreKey>, FormatError> {
    if let Some(number) = stem.strip_prefix("set-") {
        return decimal(number).map(|number| number.map(StoreKey::DeviceSet));
    }
    hex_id(stem).map(|id| id.map(StoreKey::DeviceCertificate))
}

fn shard(fanout: &str, stem: &str) -> Result<Option<StoreKey>, FormatError> {
    let Some(id) = hex_id::<ShardId>(stem)? else {
        return Ok(None);
    };
    if !hex::is_hex_shaped(fanout) {
        return Ok(None);
    }
    if fanout.len() != 2 || !stem.starts_with(fanout) {
        return Err(FormatError::NameMismatch);
    }
    Ok(Some(StoreKey::Shard(id)))
}

/// A hex ID: `None` if the text is not hex-shaped, `NameMismatch` if it is but not canonical.
fn hex_id<T: FromStr>(text: &str) -> Result<Option<T>, FormatError> {
    if !hex::is_hex_shaped(text) {
        return Ok(None);
    }
    text.parse()
        .map(Some)
        .map_err(|_| FormatError::NameMismatch)
}

/// A decimal counter: `None` if the text is not digits, `NameMismatch` if not canonical.
fn decimal<T: FromStr>(text: &str) -> Result<Option<T>, FormatError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    text.parse()
        .map(Some)
        .map_err(|_| FormatError::NameMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard_id() -> ShardId {
        let mut bytes = [0x11u8; 32];
        bytes[0] = 0xab;
        ShardId::try_from_bytes(bytes).expect("non-zero")
    }

    #[test]
    fn every_pattern_round_trips() {
        let keys = [
            StoreKey::Config(ConfigSeq::FIRST),
            StoreKey::Root(RootSeq::FIRST),
            StoreKey::Root(RootSeq::try_new(u64::MAX).expect("non-zero")),
            StoreKey::Slot(SlotId::try_from_bytes([0x5a; 16]).expect("non-zero")),
            StoreKey::Keyring(KeyringGen::FIRST),
            StoreKey::Epoch(Epoch::try_new(12).expect("non-zero")),
            StoreKey::VaultSigningKey,
            StoreKey::LogKey,
            StoreKey::DeviceCertificate(DeviceId::try_from_bytes([0x01; 16]).expect("non-zero")),
            StoreKey::DeviceSet(DeviceSetSeq::try_new(3).expect("non-zero")),
            StoreKey::Shard(shard_id()),
        ];
        for key in keys {
            let name = key.to_string();
            assert_eq!(StoreKey::parse(&name), Ok(Some(key)), "{name}");
        }
    }

    #[test]
    fn canonical_names() {
        assert_eq!(
            StoreKey::Root(RootSeq::FIRST).to_string(),
            "roots/00000000000000000001.chx"
        );
        assert_eq!(
            StoreKey::Epoch(Epoch::FIRST).to_string(),
            "keys/epoch-1.chx"
        );
        let name = StoreKey::Shard(shard_id()).to_string();
        assert_eq!(name, format!("shards/ab/ab{}.chx", "11".repeat(31)));
    }

    #[test]
    fn non_canonical_names_are_mismatches() {
        let shard = format!("ab{}", "11".repeat(31));
        for name in [
            "roots/0000000000000000001.chx".to_owned(),
            "roots/000000000000000000001.chx".to_owned(),
            "roots/00000000000000000000.chx".to_owned(),
            "roots/99999999999999999999.chx".to_owned(),
            format!("keys/slot-{}.chx", "5A".repeat(16)),
            format!("keys/slot-{}.chx", "5a".repeat(15)),
            "keys/epoch-01.chx".to_owned(),
            "configs/01.chx".to_owned(),
            "configs/0.chx".to_owned(),
            "keys/epoch-0.chx".to_owned(),
            "devices/set-007.chx".to_owned(),
            format!("shards/cd/{shard}.chx"),
            format!("shards/AB/{shard}.chx"),
            format!("shards/{}/{}.chx", "AB", shard.to_uppercase()),
        ] {
            assert_eq!(
                StoreKey::parse(&name),
                Err(FormatError::NameMismatch),
                "{name}"
            );
        }
    }

    #[test]
    fn other_names_are_ignored() {
        for name in [
            "",
            "notes.txt",
            "config.chx",
            "config.chx.tmp",
            "configs/latest.chx",
            "roots/abc.chx",
            "roots/1.tmp",
            "keys/unknown.chx",
            "keys/epoch-x.chx",
            "devices/laptop.chx",
            "shards/ab/notes.chx",
            "shards/zz/abababababababababababababababababababababababababababababababab.chx",
            "a/b/c/d.chx",
        ] {
            assert_eq!(StoreKey::parse(name), Ok(None), "{name}");
        }
    }

    #[test]
    fn type_must_match_the_name() {
        let config = StoreKey::Config(ConfigSeq::FIRST);
        assert_eq!(config.check_type(FileType::VaultConfig), Ok(()));
        assert_eq!(
            config.check_type(FileType::VaultRoot),
            Err(FormatError::NameMismatch)
        );
        assert_eq!(
            StoreKey::Shard(shard_id()).max_file_len(),
            20 + 16 * 1024 * 1024 + 168
        );
    }
}
