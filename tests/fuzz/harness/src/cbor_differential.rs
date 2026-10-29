//! Our validator and the minicbor oracle agree on what is format 0 CBOR.

use crypthix_types::cbor::{Document, Limits};

use crate::oracle::{OracleLimits, accepts};

/// The [`OracleLimits::SMALL`] values as `crypthix-types` limits.
pub const SMALL: Limits = Limits::FORMAT_0
    .with_max_document_len(OracleLimits::SMALL.max_document_len)
    .with_max_depth(OracleLimits::SMALL.max_depth)
    .with_max_container_len(OracleLimits::SMALL.max_container_len)
    .with_max_total_items(OracleLimits::SMALL.max_total_items)
    .with_max_string_len(OracleLimits::SMALL.max_string_len);

/// Compares acceptance only: the error name follows our byte-order rule (FS-93), which the
/// vectors pin, and minicbor has no equivalent.
///
/// # Panics
///
/// If our validator and the oracle disagree.
pub fn cbor_differential(data: &[u8]) {
    for (limits, oracle_limits) in [
        (Limits::FORMAT_0, OracleLimits::FS_11),
        (SMALL, OracleLimits::SMALL),
    ] {
        let ours = Document::parse(data, &limits);
        let oracle = accepts(data, &oracle_limits);
        assert_eq!(
            ours.is_ok(),
            oracle,
            "validator says {ours:?}, oracle says {oracle} for {data:02x?} under {limits:?}"
        );
    }
}
