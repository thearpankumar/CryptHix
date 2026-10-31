//! Argon2id parameters, checked against the floors and ceilings of FS-41.

use crypthix_types::format_error::FormatError;

/// Argon2id parameters that passed the bounds of FS-41.
///
/// They are checked before the KDF runs and before any memory is allocated: the floors stop a
/// tampered file from weakening the KDF, and the ceilings stop it from hanging the daemon.
///
/// ```
/// use crypthix_crypto::argon2id::KdfParams;
/// use crypthix_types::format_error::FormatError;
///
/// assert!(KdfParams::new(262_144, 3, 1).is_ok());
/// assert_eq!(KdfParams::new(65_536, 3, 1).err(), Some(FormatError::KdfBelowFloor));
/// assert_eq!(KdfParams::new(4_194_304, 32, 4).err(), Some(FormatError::KdfAboveCeiling));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    parallelism: u8,
}

impl KdfParams {
    /// Smallest memory cost in KiB (256 MiB).
    pub const MIN_M_COST: u32 = 262_144;
    /// Largest memory cost in KiB (4 GiB).
    pub const MAX_M_COST: u32 = 4_194_304;
    /// Smallest number of passes.
    pub const MIN_T_COST: u32 = 3;
    /// Largest number of passes.
    pub const MAX_T_COST: u32 = 32;
    /// Smallest parallelism.
    pub const MIN_PARALLELISM: u8 = 1;
    /// Largest parallelism.
    pub const MAX_PARALLELISM: u8 = 4;
    /// Largest `m_cost × t_cost` in KiB·passes (16 GiB·passes).
    pub const MAX_M_TIMES_T: u64 = 16_777_216;

    /// Checks parameters read from a share slot.
    ///
    /// # Errors
    ///
    /// [`FormatError::KdfBelowFloor`] if any parameter is below its floor, otherwise
    /// [`FormatError::KdfAboveCeiling`] if any is above its ceiling or `m_cost × t_cost` is.
    pub const fn new(m_cost: u32, t_cost: u32, parallelism: u8) -> Result<Self, FormatError> {
        if m_cost < Self::MIN_M_COST
            || t_cost < Self::MIN_T_COST
            || parallelism < Self::MIN_PARALLELISM
        {
            return Err(FormatError::KdfBelowFloor);
        }
        if m_cost > Self::MAX_M_COST
            || t_cost > Self::MAX_T_COST
            || parallelism > Self::MAX_PARALLELISM
            || (m_cost as u64) * (t_cost as u64) > Self::MAX_M_TIMES_T
        {
            return Err(FormatError::KdfAboveCeiling);
        }
        Ok(Self {
            m_cost,
            t_cost,
            parallelism,
        })
    }

    /// Parameters below the floors, for fast unit tests of the derivation only.
    #[cfg(test)]
    pub(crate) const fn new_for_tests(m_cost: u32, t_cost: u32, parallelism: u8) -> Self {
        Self {
            m_cost,
            t_cost,
            parallelism,
        }
    }

    /// Memory cost in KiB.
    #[must_use]
    pub const fn m_cost(&self) -> u32 {
        self.m_cost
    }

    /// Number of passes.
    #[must_use]
    pub const fn t_cost(&self) -> u32 {
        self.t_cost
    }

    /// Parallelism.
    #[must_use]
    pub const fn parallelism(&self) -> u8 {
        self.parallelism
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BELOW: Result<KdfParams, FormatError> = Err(FormatError::KdfBelowFloor);
    const ABOVE: Result<KdfParams, FormatError> = Err(FormatError::KdfAboveCeiling);

    #[test]
    fn floors_hold_at_their_value_and_fail_one_below() {
        assert!(
            KdfParams::new(262_144, 3, 1).is_ok(),
            "every floor at its value"
        );
        assert_eq!(KdfParams::new(262_143, 3, 1), BELOW);
        assert_eq!(KdfParams::new(262_144, 2, 1), BELOW);
        assert_eq!(KdfParams::new(262_144, 3, 0), BELOW);
    }

    #[test]
    fn ceilings_hold_at_their_value_and_fail_one_above() {
        assert!(
            KdfParams::new(4_194_304, 4, 4).is_ok(),
            "m and p at their ceilings"
        );
        assert_eq!(KdfParams::new(4_194_305, 3, 1), ABOVE);
        assert!(KdfParams::new(262_144, 32, 1).is_ok(), "t at its ceiling");
        assert_eq!(KdfParams::new(262_144, 33, 1), ABOVE);
        assert_eq!(KdfParams::new(262_144, 3, 5), ABOVE);
    }

    #[test]
    fn memory_times_passes_has_its_own_ceiling() {
        assert!(
            KdfParams::new(524_288, 32, 1).is_ok(),
            "exactly 16 GiB·passes"
        );
        assert_eq!(KdfParams::new(524_289, 32, 1), ABOVE);
        assert_eq!(KdfParams::new(4_194_304, 5, 1), ABOVE);
    }

    #[test]
    fn floor_wins_over_ceiling() {
        assert_eq!(KdfParams::new(1, 33, 1), BELOW);
    }
}
