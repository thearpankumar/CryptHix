//! The Argon2id derivation of a passphrase wrapping key (section 9.1).

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use crate::argon2id::{DeriveError, KdfParams};
use crate::key::check_nonzero;
use crate::key::sealed;
use crate::key::{Passphrase, SealKey};

/// The wrapping key of a passphrase slot: `Argon2id(passphrase, salt, m, t, p, 32)`, version
/// 0x13 (section 9.1).
///
/// This allocates `m_cost` KiB, which it wipes before freeing, and takes about a second at
/// calibrated parameters.
///
/// # Errors
///
/// - [`DeriveError::ZeroSalt`] if the salt is all zero (FS-03).
/// - [`DeriveError::OutOfMemory`] if the memory cannot be allocated.
///
/// # Panics
///
/// Only on a bug: if the Argon2 implementation rejects parameters that passed [`KdfParams`], a
/// 32-byte salt and output, or the block count it asked for.
pub fn derive(
    passphrase: &Passphrase,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<SealKey, DeriveError> {
    check_nonzero::check_nonzero(salt).map_err(|_| DeriveError::ZeroSalt)?;
    let params = Params::new(
        params.m_cost(),
        params.t_cost(),
        u32::from(params.parallelism()),
        Some(32),
    )
    .expect("Argon2 accepts every parameter set within the FS-41 bounds");
    let mut blocks: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    blocks
        .try_reserve_exact(params.block_count())
        .map_err(|_| DeriveError::OutOfMemory)?;
    blocks.resize(params.block_count(), Block::default());
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            salt,
            out.as_mut_slice(),
            blocks.as_mut_slice(),
        )
        .expect("Argon2 accepts a 32-byte salt and output and enough blocks");
    Ok(sealed::from_material(*out))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let passphrase = Passphrase::new("correct horse".to_owned());
        let result = derive(&passphrase, &[0; 32], &params);
        assert_eq!(result.err(), Some(DeriveError::ZeroSalt));
    }

    #[test]
    fn passes_every_parameter_in_its_place() {
        // Distinct t and p, so swapping them changes the output.
        let params = KdfParams::new_for_tests(64, 3, 2);
        let passphrase = Passphrase::new("password".to_owned());
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
        let passphrase = Passphrase::new("correct horse battery staple".to_owned());
        let key = derive(&passphrase, &[7; 32], &params).expect("derives");
        let expected = reference(b"correct horse battery staple", &[7; 32], 262_144, 3, 1);
        assert_eq!(sealed::material(&key), &expected);
    }
}
