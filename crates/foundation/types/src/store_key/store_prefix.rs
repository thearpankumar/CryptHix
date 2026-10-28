//! Prefixes for listing a store.

use std::fmt;

use crate::store_key::StoreKey;

/// A directory of a store that a backend can list.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum StorePrefix {
    /// `configs/`.
    Configs,
    /// `roots/`.
    Roots,
    /// `keys/`.
    Keys,
    /// `devices/`.
    Devices,
    /// `shards/`, every fan-out directory.
    Shards,
    /// `shards/<2 hex>/`, one fan-out directory.
    ShardFanout(u8),
}

impl StorePrefix {
    /// Whether `key` lies under this prefix.
    #[must_use]
    pub fn contains(&self, key: &StoreKey) -> bool {
        match (self, key) {
            (StorePrefix::Configs, StoreKey::Config(_))
            | (StorePrefix::Roots, StoreKey::Root(_))
            | (StorePrefix::Shards, StoreKey::Shard(_)) => true,
            (StorePrefix::Keys, key) => matches!(
                key,
                StoreKey::Slot(_)
                    | StoreKey::Keyring(_)
                    | StoreKey::Epoch(_)
                    | StoreKey::VaultSigningKey
                    | StoreKey::LogKey
            ),
            (StorePrefix::Devices, key) => {
                matches!(key, StoreKey::DeviceCertificate(_) | StoreKey::DeviceSet(_))
            }
            (StorePrefix::ShardFanout(fanout), StoreKey::Shard(id)) => id.as_bytes()[0] == *fanout,
            _ => false,
        }
    }
}

impl fmt::Display for StorePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorePrefix::Configs => f.write_str("configs/"),
            StorePrefix::Roots => f.write_str("roots/"),
            StorePrefix::Keys => f.write_str("keys/"),
            StorePrefix::Devices => f.write_str("devices/"),
            StorePrefix::Shards => f.write_str("shards/"),
            StorePrefix::ShardFanout(fanout) => write!(f, "shards/{fanout:02x}/"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::id::{ConfigSeq, RootSeq, ShardId};

    #[test]
    fn prefixes() {
        let shard = StoreKey::Shard(ShardId::try_from_bytes([0x0c; 32]).expect("non-zero"));
        assert!(
            StorePrefix::Shards.contains(&shard),
            "shards/ holds every shard"
        );
        assert!(
            StorePrefix::ShardFanout(0x0c).contains(&shard),
            "fan-out by first byte"
        );
        assert!(
            !StorePrefix::ShardFanout(0x0d).contains(&shard),
            "other fan-out"
        );
        assert!(
            !StorePrefix::Roots.contains(&shard),
            "a shard is not a root"
        );
        assert!(
            StorePrefix::Roots.contains(&StoreKey::Root(RootSeq::FIRST)),
            "roots/ holds roots"
        );
        assert!(
            StorePrefix::Keys.contains(&StoreKey::VaultSigningKey),
            "keys/ holds key files"
        );
        let config = StoreKey::Config(ConfigSeq::FIRST);
        assert!(
            !StorePrefix::Keys.contains(&config),
            "configs are not key files"
        );
        assert!(
            StorePrefix::Configs.contains(&config),
            "configs list under configs/"
        );
        assert_eq!(StorePrefix::ShardFanout(0x0c).to_string(), "shards/0c/");
    }
}
