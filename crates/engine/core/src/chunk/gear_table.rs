//! The secret per-vault gear table (FS-52).

use std::fmt;

use crypthix_crypto::kdf::{self, KdfContext};
use crypthix_crypto::key::{KdfKey, XofKey};
use crypthix_crypto::label::XofKeyLabel;
use crypthix_crypto::mac;
use crypthix_crypto::secure_mem::{MemError, SecretBuf};
use crypthix_types::id::VaultId;

use crate::limits::GEAR_TABLE_LEN;

/// The 256-word gear table of FastCDC, made from the vault's `chunker_seed` so a backend cannot
/// recompute chunk boundaries (FS-52, M-39).
///
/// It is the first 2,048 bytes of the keyed BLAKE3 XOF under
/// `K_gear = KDF(chunker_seed, -, kdf/gear, vault_id)` over the empty input, read as
/// little-endian `u64` words. The shifted table that FastCDC also uses is computed from it as
/// each word is read. It is kept in a [`SecretBuf`]: plaintext memory, wiped on free and, on
/// Linux, locked where `RLIMIT_MEMLOCK` allows and left out of core dumps and forked children
/// (plain heap memory elsewhere and under Miri), but not in secret pages as keys are, which
/// fits the design's assumption that the seed may leak anyway: keyed gear tables have been
/// recovered from observed chunk sizes (ePrint 2025/558). Padmé coarsens those sizes and packs
/// hide them (T-84). Only ordinary objects are cut with it; secret-class objects are cut at
/// fixed 1 MiB steps and never index it with their bytes (FS-52).
pub struct GearTable(SecretBuf);

impl GearTable {
    /// Derives the table of a vault.
    ///
    /// # Errors
    ///
    /// [`MemError`] if protected memory cannot be allocated for `K_gear` or the table.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after `chunker_seed` was made.
    pub fn derive(chunker_seed: &KdfKey, vault_id: &VaultId) -> Result<Self, MemError> {
        let context = KdfContext::new().field(vault_id.as_bytes());
        let key: XofKey = kdf::kdf(chunker_seed, None, XofKeyLabel::Gear, &context)?;
        #[cfg(test)]
        crate::fault::allocation()?;
        let mut table = SecretBuf::try_zeroed(GEAR_TABLE_LEN)?;
        mac::xof(&key, table.as_mut_slice());
        Ok(Self(table))
    }

    /// The 256 words as little-endian bytes. The table is made with exactly 2,048 bytes, so this
    /// is never `None`; the conversion is checked rather than asserted so the data path cannot
    /// panic, and a cut is free of bounds checks once it has the array.
    pub(crate) fn words(&self) -> Option<&[[u8; 8]; 256]> {
        let (words, _) = self.0.as_slice().as_chunks::<8>();
        words.try_into().ok()
    }

    /// The words as numbers, for the tests that compare with fastcdc.
    #[cfg(test)]
    pub(crate) fn to_u64s(&self) -> Vec<u64> {
        self.words()
            .expect("256 words")
            .iter()
            .map(|word| u64::from_le_bytes(*word))
            .collect()
    }
}

/// Prints nothing of the table.
impl fmt::Debug for GearTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GearTable(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{self, Fault};
    use crate::test_data::gear_table as table;

    #[test]
    fn no_protected_memory_fails_with_memory() {
        let key = KdfKey::from_bytes([3; 32]).expect("non-zero key");
        let vault_id = VaultId::try_from_bytes([0x11; 16]).expect("non-zero ID");
        let _guard = fault::inject(Fault::Allocation(0));
        assert_eq!(
            GearTable::derive(&key, &vault_id).map(|_| ()),
            Err(MemError::MapFailed)
        );
    }

    #[test]
    fn the_table_is_the_gear_xof_of_the_vault() {
        let key = KdfKey::from_bytes([3; 32]).expect("non-zero key");
        let vault_id = VaultId::try_from_bytes([0x11; 16]).expect("non-zero ID");
        let context = KdfContext::new().field(vault_id.as_bytes());
        let xof_key: XofKey = kdf::kdf(&key, None, XofKeyLabel::Gear, &context).expect("derives");
        let mut expected = [0u8; GEAR_TABLE_LEN];
        mac::xof(&xof_key, &mut expected);
        let table = GearTable::derive(&key, &vault_id).expect("derives");
        assert_eq!(table.0.as_slice(), expected.as_slice());
        assert_eq!(
            table.to_u64s()[1],
            u64::from_le_bytes(expected[8..16].try_into().expect("8 bytes")),
            "words are little-endian"
        );
    }

    #[test]
    fn seed_and_vault_both_change_the_table() {
        let base = table(3).to_u64s();
        assert_eq!(base, table(3).to_u64s(), "derivation is deterministic");
        assert_ne!(base, table(4).to_u64s(), "seed ignored");
        let key = KdfKey::from_bytes([3; 32]).expect("non-zero key");
        let other_vault = VaultId::try_from_bytes([0x12; 16]).expect("non-zero ID");
        let other = GearTable::derive(&key, &other_vault).expect("derives");
        assert_ne!(base, other.to_u64s(), "vault ignored");
    }

    #[test]
    fn debug_prints_no_words() {
        assert_eq!(format!("{:?}", table(3)), "GearTable(..)");
    }
}
