//! The file-type registry (format spec section 5.1).

use crate::format_error::FormatError;

const KIB: u32 = 1024;
const MIB: u32 = 1024 * KIB;

/// A file type, the `typ` field of the preamble.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FileType {
    /// Vault config, `0x01`.
    VaultConfig,
    /// Share slot, `0x02`.
    ShareSlot,
    /// Keyring, `0x03`.
    Keyring,
    /// Epoch key file, `0x04`.
    EpochKey,
    /// Vault signing key, `0x05`.
    VaultSigningKey,
    /// Device certificate, `0x06`.
    DeviceCertificate,
    /// Device key, `0x07`. Device-local.
    DeviceKey,
    /// Shard, `0x08`.
    Shard,
    /// Vault root, `0x09`.
    VaultRoot,
    /// Device state, `0x0A`. Device-local.
    DeviceState,
    /// Log segment, `0x0B`. Reserved for Phase 3.
    LogSegment,
    /// Snapshot root, `0x0C`. Reserved for Phase 3.
    SnapshotRoot,
    /// Queue job, `0x0D`. Device-local.
    QueueJob,
    /// Log key, `0x0E`. Reserved for Phase 3.
    LogKey,
    /// Token wrapper, `0x0F`. Reserved for Phase 4.
    TokenWrapper,
    /// Device set, `0x10`.
    DeviceSet,
}

impl FileType {
    /// The only struct version of every file type in format 0.
    pub const STRUCT_VERSION: u8 = 1;

    /// Looks up a file-type code.
    ///
    /// # Errors
    ///
    /// [`FormatError::UnknownType`] for unassigned codes, nested types (`0x20`–`0x2F`) and
    /// private-use types (`0xF0`–`0xFF`) (FS-06).
    pub const fn try_from_code(code: u8) -> Result<Self, FormatError> {
        Ok(match code {
            0x01 => FileType::VaultConfig,
            0x02 => FileType::ShareSlot,
            0x03 => FileType::Keyring,
            0x04 => FileType::EpochKey,
            0x05 => FileType::VaultSigningKey,
            0x06 => FileType::DeviceCertificate,
            0x07 => FileType::DeviceKey,
            0x08 => FileType::Shard,
            0x09 => FileType::VaultRoot,
            0x0A => FileType::DeviceState,
            0x0B => FileType::LogSegment,
            0x0C => FileType::SnapshotRoot,
            0x0D => FileType::QueueJob,
            0x0E => FileType::LogKey,
            0x0F => FileType::TokenWrapper,
            0x10 => FileType::DeviceSet,
            _ => return Err(FormatError::UnknownType),
        })
    }

    /// The registry code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            FileType::VaultConfig => 0x01,
            FileType::ShareSlot => 0x02,
            FileType::Keyring => 0x03,
            FileType::EpochKey => 0x04,
            FileType::VaultSigningKey => 0x05,
            FileType::DeviceCertificate => 0x06,
            FileType::DeviceKey => 0x07,
            FileType::Shard => 0x08,
            FileType::VaultRoot => 0x09,
            FileType::DeviceState => 0x0A,
            FileType::LogSegment => 0x0B,
            FileType::SnapshotRoot => 0x0C,
            FileType::QueueJob => 0x0D,
            FileType::LogKey => 0x0E,
            FileType::TokenWrapper => 0x0F,
            FileType::DeviceSet => 0x10,
        }
    }

    /// The largest `body_len` allowed for this type (FS-07).
    #[must_use]
    pub const fn max_body_len(self) -> u32 {
        match self {
            FileType::Keyring | FileType::VaultSigningKey | FileType::LogKey => 4 * KIB,
            FileType::VaultConfig
            | FileType::ShareSlot
            | FileType::DeviceCertificate
            | FileType::DeviceKey
            | FileType::DeviceState
            | FileType::TokenWrapper => 64 * KIB,
            FileType::VaultRoot
            | FileType::SnapshotRoot
            | FileType::QueueJob
            | FileType::DeviceSet => MIB,
            FileType::EpochKey | FileType::LogSegment => 16 * MIB,
            FileType::Shard => 16 * MIB + 168,
        }
    }
}

impl TryFrom<u8> for FileType {
    type Error = FormatError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Self::try_from_code(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for code in 0x01..=0x10 {
            let file_type = FileType::try_from_code(code).expect("assigned code");
            assert_eq!(file_type.code(), code);
        }
    }

    #[test]
    fn unassigned_nested_and_private_codes_are_rejected() {
        for code in [0x00, 0x11, 0x1F, 0x20, 0x23, 0x2F, 0x30, 0xEF, 0xF0, 0xFF] {
            assert_eq!(
                FileType::try_from_code(code),
                Err(FormatError::UnknownType),
                "code {code:#04x}"
            );
        }
    }

    #[test]
    fn caps_match_the_spec_table() {
        assert_eq!(FileType::VaultConfig.max_body_len(), 65_536);
        assert_eq!(FileType::Keyring.max_body_len(), 4_096);
        assert_eq!(FileType::EpochKey.max_body_len(), 16_777_216);
        assert_eq!(FileType::Shard.max_body_len(), 16_777_384);
        assert_eq!(FileType::VaultRoot.max_body_len(), 1_048_576);
        assert_eq!(FileType::DeviceSet.max_body_len(), 1_048_576);
    }
}
