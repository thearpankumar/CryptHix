//! Deterministic inputs shared by the unit tests.

use std::ops::Range;

use crypthix_crypto::key::{KdfKey, XofKey};
use crypthix_crypto::mac;
use crypthix_types::id::VaultId;

use crate::blob::ObjectClass;
use crate::chunk::{ChunkParams, Chunks, GearTable};

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

/// The most chunks `len` bytes of an object of `class` can be cut into: every chunk but the
/// last is at least the minimum (the maximum for the secret class) and the last is not empty.
/// A loop over a chunker that goes past it is not advancing and must fail, not run on until
/// it fills memory.
pub(crate) fn most_chunks(class: ObjectClass, params: &ChunkParams, len: usize) -> usize {
    let least = match class {
        ObjectClass::Ordinary => params.min,
        ObjectClass::Secret => params.max,
    };
    len / least + 1
}

/// The ranges [`Chunks`] cuts `data` into, checked as they come: each must be non-empty, start
/// where the one before ended and stay within `data`, and there must be no more than
/// [`most_chunks`]. A cut that stops advancing panics here at once instead of growing the list
/// without end.
pub(crate) fn chunk_ranges(
    gear: &GearTable,
    class: ObjectClass,
    data: &[u8],
    params: ChunkParams,
) -> Vec<Range<usize>> {
    let most = most_chunks(class, &params, data.len());
    let mut ranges: Vec<Range<usize>> = Vec::new();
    let mut end = 0;
    for range in Chunks::with_params(gear, class, data, params) {
        assert!(
            ranges.len() < most,
            "more than {most} chunks of {} bytes: the chunker is not advancing",
            data.len()
        );
        assert!(
            range.start == end && range.start < range.end && range.end <= data.len(),
            "chunk {range:?} after offset {end} of {} bytes",
            data.len()
        );
        end = range.end;
        ranges.push(range);
    }
    ranges
}
