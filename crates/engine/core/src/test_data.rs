//! Deterministic inputs shared by the unit tests.

use crypthix_crypto::key::{KdfKey, XofKey};
use crypthix_crypto::mac;
use crypthix_types::id::VaultId;

use crate::chunk::GearTable;

/// `len` deterministic pseudo-random bytes: the keyed XOF under `[seed; 32]`.
pub(crate) fn pseudo_random(seed: u8, len: usize) -> Vec<u8> {
    let key = XofKey::from_bytes([seed; 32]).expect("non-zero key");
    let mut data = vec![0u8; len];
    mac::xof(&key, &mut data);
    data
}

/// The gear table of chunker seed `[seed; 32]` in vault `[0x11; 16]`.
pub(crate) fn gear_table(seed: u8) -> GearTable {
    let key = KdfKey::from_bytes([seed; 32]).expect("non-zero key");
    let vault_id = VaultId::try_from_bytes([0x11; 16]).expect("non-zero ID");
    GearTable::derive(&key, &vault_id).expect("derives")
}
