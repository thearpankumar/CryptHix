//! The cut points: FastCDC 2020 for ordinary objects, fixed size for secret ones (FS-52).

use crate::blob::ObjectClass;
use crate::chunk::{ChunkParams, GearTable};

/// The length of the first chunk of `data` in an object of `class` (FS-52). The ordinary class
/// takes the keyed FastCDC cut: all of `data` if it is no longer than the minimum, otherwise
/// between the minimum and the maximum, and zero only for empty `data`. The secret class takes
/// the maximum, or all of `data` if it is shorter, and reads no byte of it: the FastCDC loop
/// indexes the gear table with plaintext bytes and stops early where it cuts, which a process
/// sharing the cache can time, and secret chunks never deduplicate, so content-defined cuts
/// would give them nothing (T-84).
pub(crate) fn cut_for(
    class: ObjectClass,
    gear: &GearTable,
    data: &[u8],
    params: &ChunkParams,
) -> usize {
    match class {
        ObjectClass::Ordinary => cut_with(gear, data, params),
        ObjectClass::Secret => data.len().min(params.max),
    }
}

/// The keyed FastCDC cut of an ordinary object, with any sizes and masks: the loop of
/// `fastcdc::v2020::cut_gear` 5.0.0, with `gear_ls[b]` computed as `gear[b] << 1`.
fn cut_with(gear: &GearTable, data: &[u8], params: &ChunkParams) -> usize {
    let mut remaining = data.len();
    if remaining <= params.min {
        return remaining;
    }
    let mut center = params.avg;
    if remaining > params.max {
        remaining = params.max;
    } else if remaining < center {
        center = remaining;
    }
    // Always 256 words; were it ever not, cutting at the maximum keeps the chunks valid.
    let Some(words) = gear.words() else {
        debug_assert!(false, "a gear table has 256 words");
        return remaining;
    };
    let gear_at = |byte: u8| u64::from_le_bytes(words[usize::from(byte)]);
    let (strict, loose) = (params.mask_s, params.mask_l);
    let (strict_shifted, loose_shifted) = (strict << 1, loose << 1);
    // The pairs of bytes the loop takes; an odd last byte is never tested (FS-52). Iterating
    // them instead of indexing keeps the loop free of bounds checks and panics.
    let (pairs, _) = data.get(..remaining).unwrap_or(data).as_chunks::<2>();
    // `min <= center <= remaining`, so both splits are in range.
    let (strict_pairs, loose_pairs) = pairs.split_at_checked(center / 2).unwrap_or((pairs, &[]));
    let first = params.min / 2;

    let mut hash: u64 = 0;
    for (index, &[even, odd]) in strict_pairs.iter().enumerate().skip(first) {
        let a = index * 2;
        hash = (hash << 2).wrapping_add(gear_at(even) << 1);
        if hash & strict_shifted == 0 {
            return a;
        }
        hash = hash.wrapping_add(gear_at(odd));
        if hash & strict == 0 {
            return a + 1;
        }
    }
    let skipped = first.saturating_sub(strict_pairs.len());
    for (offset, &[even, odd]) in loose_pairs.iter().enumerate().skip(skipped) {
        let a = (strict_pairs.len() + offset) * 2;
        hash = (hash << 2).wrapping_add(gear_at(even) << 1);
        if hash & loose_shifted == 0 {
            return a;
        }
        hash = hash.wrapping_add(gear_at(odd));
        if hash & loose == 0 {
            return a + 1;
        }
    }
    remaining
}

#[cfg(test)]
mod tests {
    use fastcdc::v2020;
    use proptest::prelude::{Strategy, prop_assert_eq, prop_oneof, proptest};

    use super::*;
    use crate::limits::{MAX_CHUNK, MIN_CHUNK};
    use crate::test_data::gear_table as table;
    use crate::test_data::{any_byte, bytes, chunk_ranges, pseudo_random};

    /// The first format 0 cut of `data` in an ordinary object.
    fn cut(gear: &GearTable, data: &[u8]) -> usize {
        cut_for(ObjectClass::Ordinary, gear, data, &ChunkParams::FORMAT_0)
    }

    /// The chunk lengths fastcdc cuts from `data` with `gear`'s words.
    fn fastcdc_lengths(gear: &GearTable, data: &[u8], params: &ChunkParams) -> Vec<usize> {
        let words = gear.to_u64s();
        let shifted: Vec<u64> = words.iter().map(|word| word << 1).collect();
        let mut lengths = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let (_, len) = v2020::cut_gear(
                &data[offset..],
                params.min,
                params.avg,
                params.max,
                params.mask_s,
                params.mask_l,
                params.mask_s << 1,
                params.mask_l << 1,
                &words,
                &shifted,
            );
            lengths.push(len);
            offset += len;
        }
        lengths
    }

    fn our_lengths(gear: &GearTable, data: &[u8], params: &ChunkParams) -> Vec<usize> {
        chunk_ranges(gear, ObjectClass::Ordinary, data, *params)
            .into_iter()
            .map(|range| range.len())
            .collect()
    }

    #[test]
    fn short_input_is_one_chunk_and_empty_input_none() {
        let gear = table(1);
        assert_eq!(cut(&gear, &[]), 0);
        assert_eq!(cut(&gear, &[7]), 1);
        let data = pseudo_random(2, MIN_CHUNK + 1);
        assert_eq!(
            cut(&gear, &data[..MIN_CHUNK]),
            MIN_CHUNK,
            "the minimum is one chunk"
        );
        assert!(cut(&gear, &data) >= MIN_CHUNK);
    }

    #[test]
    #[cfg_attr(miri, ignore = "megabytes of input are slow under Miri")]
    fn a_secret_cut_depends_on_the_length_only() {
        let params = ChunkParams::FORMAT_0;
        for len in [0, 1, MIN_CHUNK, MAX_CHUNK - 1, MAX_CHUNK, MAX_CHUNK + 1] {
            let random = cut_for(
                ObjectClass::Secret,
                &table(1),
                &pseudo_random(1, len),
                &params,
            );
            let zeros = cut_for(ObjectClass::Secret, &table(2), &vec![0; len], &params);
            assert_eq!((random, zeros), (len.min(MAX_CHUNK), len.min(MAX_CHUNK)));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "megabytes of input are slow under Miri")]
    fn zeros_are_cut_at_the_maximum() {
        let gear = table(1);
        let zeros = vec![0u8; 3 * MAX_CHUNK + 5];
        assert_eq!(
            our_lengths(&gear, &zeros, &ChunkParams::FORMAT_0),
            fastcdc_lengths(&gear, &zeros, &ChunkParams::FORMAT_0)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "megabytes of input are slow under Miri")]
    fn full_size_chunks_match_fastcdc() {
        for (seed, len) in [(1, 8 << 20), (2, 3 * MAX_CHUNK + 1), (3, MIN_CHUNK + 1)] {
            let gear = table(seed);
            let data = pseudo_random(seed, len);
            let ours = our_lengths(&gear, &data, &ChunkParams::FORMAT_0);
            assert_eq!(ours, fastcdc_lengths(&gear, &data, &ChunkParams::FORMAT_0));
            assert_eq!(ours.iter().sum::<usize>(), len);
            let (last, rest) = ours.split_last().expect("non-empty input has chunks");
            assert!(*last > 0 && *last <= MAX_CHUNK);
            for len in rest {
                assert!((MIN_CHUNK..=MAX_CHUNK).contains(len), "{len}");
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "megabytes of input are slow under Miri")]
    fn the_average_is_near_256_kib() {
        let gear = table(5);
        let data = pseudo_random(5, 32 << 20);
        let lengths = our_lengths(&gear, &data, &ChunkParams::FORMAT_0);
        let average = data.len() / lengths.len();
        assert!(
            (128 << 10..=512 << 10).contains(&average),
            "average chunk of {average} bytes"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "megabytes of input are slow under Miri")]
    fn a_different_seed_moves_the_boundaries() {
        let data = pseudo_random(9, 4 << 20);
        let first = our_lengths(&table(1), &data, &ChunkParams::FORMAT_0);
        let second = our_lengths(&table(2), &data, &ChunkParams::FORMAT_0);
        assert_ne!(first, second);
    }

    #[test]
    #[cfg_attr(miri, ignore = "megabytes of input are slow under Miri")]
    fn an_edit_in_the_middle_changes_few_chunks() {
        let gear = table(4);
        let data = pseudo_random(4, 8 << 20);
        let mut edited = data.clone();
        edited[4 << 20] ^= 1;
        let params = ChunkParams::FORMAT_0;
        let before: Vec<&[u8]> = chunk_ranges(&gear, ObjectClass::Ordinary, &data, params)
            .into_iter()
            .map(|r| &data[r])
            .collect();
        let after: Vec<&[u8]> = chunk_ranges(&gear, ObjectClass::Ordinary, &edited, params)
            .into_iter()
            .map(|r| &edited[r])
            .collect();
        let changed = after.iter().filter(|chunk| !before.contains(chunk)).count();
        assert!((1..=2).contains(&changed), "{changed} chunks changed");
    }

    /// Bytes that cut often: random, a small alphabet, or long runs.
    fn data() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            bytes(0..8_000, any_byte),
            bytes(0..8_000, |byte| byte % 4),
            bytes(0..4_000, |byte| if byte & 1 == 0 { 0 } else { 255 }),
        ]
    }

    proptest! {
        #[test]
        fn scaled_chunks_match_fastcdc(seed in 1u8.., data in data()) {
            let gear = table(seed);
            let params = ChunkParams::SCALED;
            prop_assert_eq!(our_lengths(&gear, &data, &params), fastcdc_lengths(&gear, &data, &params));
        }
    }
}
