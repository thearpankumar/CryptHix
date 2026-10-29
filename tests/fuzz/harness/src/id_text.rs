//! ID and counter text: canonical text round-trips, and nothing panics (FS-92).

use std::fmt::Display;
use std::str::FromStr;

use crypthix_types::id::{CertSeq, ConfigSeq, DeviceId, DeviceSetSeq, Epoch, KeyId, KeyringGen};
use crypthix_types::id::{LogSeq, ObjectVersion, RootSeq, SenderId, ShardId, ShareSetId};
use crypthix_types::id::{ShareSetVersion, SlotId, VaultId, VaultNonce};

/// Parses `text` as `T`; if it is accepted, it must print back exactly.
fn round_trip<T: FromStr + Display>(text: &str) {
    if let Ok(value) = text.parse::<T>() {
        assert_eq!(
            value.to_string(),
            text,
            "an ID or counter has one canonical text"
        );
    }
}

/// Parses `data`, when it is UTF-8, as every clear ID (lowercase hex) and every counter
/// (decimal without leading zeros).
///
/// # Panics
///
/// If an accepted text does not print back exactly.
pub fn id_text(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    round_trip::<VaultId>(text);
    round_trip::<VaultNonce>(text);
    round_trip::<DeviceId>(text);
    round_trip::<SlotId>(text);
    round_trip::<ShareSetId>(text);
    round_trip::<SenderId>(text);
    round_trip::<ShardId>(text);
    round_trip::<KeyId>(text);
    round_trip::<Epoch>(text);
    round_trip::<KeyringGen>(text);
    round_trip::<ShareSetVersion>(text);
    round_trip::<RootSeq>(text);
    round_trip::<ConfigSeq>(text);
    round_trip::<DeviceSetSeq>(text);
    round_trip::<CertSeq>(text);
    round_trip::<ObjectVersion>(text);
    round_trip::<LogSeq>(text);
}
