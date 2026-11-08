//! The Argon2id derivation of a passphrase wrapping key (section 9.1).

use argon2::{Algorithm, Argon2, Block, Params, Version};

use crate::argon2id::{DeriveError, KdfParams};
use crate::key::check_nonzero;
use crate::key::sealed::{self, Sealed};
use crate::key::{Passphrase, SealKey};
use crate::secure_mem::SecretVec;

/// The wrapping key of a passphrase slot: `Argon2id(passphrase, salt, m, t, p, 32)`, version
/// 0x13 (section 9.1).
///
/// This maps `m_cost` KiB of protected memory (O1), which it wipes before freeing, and takes
/// about a second at calibrated parameters. The key is written straight into its slot.
///
/// # Errors
///
/// - [`DeriveError::ZeroSalt`] if the salt is all zero (FS-03).
/// - [`DeriveError::ArgonMemory`] if the Argon2id working memory cannot be allocated.
/// - [`DeriveError::KeyMemory`] if no protected memory is free for the key.
///
/// # Panics
///
/// Only on a bug: if the Argon2 implementation rejects parameters that passed [`KdfParams`], a
/// 32-byte salt and output, or the block count it asked for. And on Linux, in a child forked
/// without `exec` after `passphrase` was made ([`secure_mem`](crate::secure_mem#fork)).
pub fn derive(
    passphrase: &Passphrase,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<SealKey, DeriveError> {
    derive_keeping_blocks(passphrase, salt, params).map(|(key, _blocks)| key)
}

/// [`derive()`], also handing back the Argon2id working memory, still filled, so tests can see
/// the level it got. The caller drops it, which wipes it.
fn derive_keeping_blocks(
    passphrase: &Passphrase,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<(SealKey, SecretVec<Block>), DeriveError> {
    check_nonzero::check_nonzero(salt).map_err(|_| DeriveError::ZeroSalt)?;
    let params = Params::new(
        params.m_cost(),
        params.t_cost(),
        u32::from(params.parallelism()),
        Some(32),
    )
    .expect("Argon2 accepts every parameter set within the FS-41 bounds");
    let mut key = SealKey::zeroed(sealed::TOKEN)?;
    let mut blocks =
        SecretVec::<Block>::try_new(params.block_count()).map_err(|_| DeriveError::ArgonMemory)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            salt,
            key.material_mut(sealed::TOKEN),
            blocks.as_mut_slice(),
        )
        .expect("Argon2 accepts a 32-byte salt and output and enough blocks");
    Ok((key, blocks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_mem::Level;

    fn reference(passphrase: &[u8], salt: &[u8], m_cost: u32, t_cost: u32, p: u32) -> [u8; 32] {
        let params = Params::new(m_cost, t_cost, p, Some(32)).expect("valid");
        let mut blocks = vec![Block::default(); params.block_count()];
        let mut out = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into_with_memory(passphrase, salt, &mut out, blocks.as_mut_slice())
            .expect("valid");
        out
    }

    #[test]
    fn zero_salt_is_rejected_before_any_work() {
        let params = KdfParams::new(262_144, 3, 1).expect("at the floor");
        let passphrase = Passphrase::new("correct horse".to_owned()).expect("a buffer");
        let result = derive(&passphrase, &[0; 32], &params);
        assert_eq!(result.err(), Some(DeriveError::ZeroSalt));
    }

    #[test]
    fn passes_every_parameter_in_its_place() {
        // Distinct t and p, so swapping them changes the output.
        let params = KdfParams::new_for_tests(64, 3, 2);
        let passphrase = Passphrase::new("password".to_owned()).expect("a buffer");
        let key = derive(&passphrase, &[1; 32], &params).expect("derives");
        assert_eq!(
            sealed::material(&key),
            &reference(b"password", &[1; 32], 64, 3, 2)
        );
        assert_ne!(
            sealed::material(&key),
            &reference(b"password", &[1; 32], 64, 2, 3)
        );
    }

    #[test]
    #[ignore = "slow: allocates 256 MiB (FS-94); run with --ignored"]
    fn derives_at_the_floor() {
        let params =
            KdfParams::new(KdfParams::MIN_M_COST, KdfParams::MIN_T_COST, 1).expect("at the floor");
        let passphrase =
            Passphrase::new("correct horse battery staple".to_owned()).expect("a buffer");
        let (key, blocks) = derive_keeping_blocks(&passphrase, &[7; 32], &params).expect("derives");
        let level = blocks.level().expect("256 MiB of blocks map memory");
        drop(blocks);
        if cfg!(all(target_os = "linux", not(miri))) {
            assert!(level >= Level::DumpExcluded, "{level}");
        } else {
            assert_eq!(level, Level::Heap);
        }
        let expected = reference(b"correct horse battery staple", &[7; 32], 262_144, 3, 1);
        assert_eq!(sealed::material(&key), &expected);
    }
}
