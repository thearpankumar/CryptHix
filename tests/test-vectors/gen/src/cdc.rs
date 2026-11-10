//! A second FastCDC 2020 chunker, written from the cut rule of FS-52 and the FastCDC 2020 paper
//! (Xia et al., normalised chunking level 2) rather than from `crypthix-core`, so TV-07 checks
//! that crate's chunker against an independent reading of the spec.
//!
//! It takes one byte per step, where the `fastcdc` crate's `v2020` module and `crypthix-core`
//! take two with a shifted table and shifted masks; the two give the same cut points, because
//! `((h << 1) + g) << 1` tested against `mask << 1` is `(h << 1) + g` tested against `mask`
//! when the mask's top bit is clear. The rule:
//! - input no longer than the minimum is one chunk, and empty input has none;
//! - the hash starts at zero at the minimum, rounded down to even, and is `(h << 1) + gear[b]`
//!   for each byte `b`;
//! - byte position `p` is tested with the strict mask while `p < 2⌊center / 2⌋`, where `center`
//!   is the average or the input length if that is shorter, and with the loose mask after;
//! - only positions below the scanned length rounded down to even are tested, so an odd last
//!   byte is never a cut point;
//! - the chunk ends just before the byte whose hash matched, or at the maximum (or the end of
//!   the input) when nothing matched.
//!
//! Secret-class objects are not cut by this rule: [`fixed_lengths`] cuts them into chunks of
//! the maximum and a shorter last one, from the length alone.

use crate::cx;
use crate::labels;

/// The minimum, average and maximum chunk sizes of format 0 (FS-52).
pub(crate) const MIN: usize = 64 * 1024;
pub(crate) const AVG: usize = 256 * 1024;
pub(crate) const MAX: usize = 1024 * 1024;

/// The strict mask for a 256 KiB average at normalisation level 2: 20 bits, entry 20 of the
/// FastCDC 2020 mask table.
pub(crate) const MASK_S: u64 = 0x0000_d917_4753_7000;

/// The loose mask: 16 bits, entry 16 of the same table.
pub(crate) const MASK_L: u64 = 0x0000_d903_0353_7000;

/// The 256 gear words of a vault: the first 2,048 bytes of the keyed BLAKE3 XOF under
/// `K_gear = KDF(chunker_seed, -, kdf/gear, vault_id)`, read as little-endian `u64`s (FS-52).
pub(crate) fn gear_table(chunker_seed: &[u8; 32], vault_id: &[u8; 16]) -> [u64; 256] {
    let key = cx::kdf(chunker_seed, None, labels::full("kdf", "gear"), vault_id);
    let mut bytes = [0u8; 2048];
    blake3::Hasher::new_keyed(&key)
        .finalize_xof()
        .fill(&mut bytes);
    let mut words = [0u64; 256];
    let (chunks, _) = bytes.as_chunks::<8>();
    for (word, chunk) in words.iter_mut().zip(chunks) {
        *word = u64::from_le_bytes(*chunk);
    }
    words
}

/// The hash after the last byte of `window`, starting from zero before its first byte. Each
/// step shifts the earlier bytes one bit further out of the 64-bit word, so the hash at
/// position `p` is this over the bytes from the larger of `2⌊min/2⌋` and `p − 63` to `p`.
pub(crate) fn hash(gear: &[u64; 256], window: &[u8]) -> u64 {
    window.iter().fold(0u64, |hash, byte| {
        (hash << 1).wrapping_add(gear[usize::from(*byte)])
    })
}

/// The length of the first chunk of `data`.
fn cut(gear: &[u64; 256], data: &[u8]) -> usize {
    let len = data.len();
    if len <= MIN {
        return len;
    }
    let end = len.min(MAX);
    let center = len.min(AVG);
    let strict_end = center & !1;
    let tested_end = end & !1;
    let mut hash = 0u64;
    for position in (MIN & !1)..tested_end {
        hash = (hash << 1).wrapping_add(gear[usize::from(data[position])]);
        let mask = if position < strict_end {
            MASK_S
        } else {
            MASK_L
        };
        if hash & mask == 0 {
            return position;
        }
    }
    end
}

/// The lengths of every chunk of `data`, in order.
pub(crate) fn lengths(gear: &[u64; 256], data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let len = cut(gear, &data[offset..]);
        out.push(len);
        offset += len;
    }
    out
}

/// The lengths of the chunks of a secret-class object of `len` bytes: the maximum, then the
/// rest, with none for an empty object (FS-52).
pub(crate) fn fixed_lengths(len: usize) -> Vec<usize> {
    let mut out = vec![MAX; len / MAX];
    if !len.is_multiple_of(MAX) {
        out.push(len % MAX);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_masks_have_20_and_16_bits_below_bit_63() {
        assert_eq!((MASK_S.count_ones(), MASK_L.count_ones()), (20, 16));
        assert_eq!(
            MASK_S & MASK_L,
            MASK_L,
            "the loose mask is part of the strict one"
        );
        assert_eq!(
            (MASK_S | MASK_L) >> 63,
            0,
            "the one-byte rule needs bit 63 clear"
        );
    }

    #[test]
    fn the_hash_forgets_bytes_64_positions_back() {
        let gear = gear_table(&[1; 32], &[2; 16]);
        let mut window = [7u8; 70];
        let last_64 = hash(&gear, &window[6..]);
        window[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(
            hash(&gear, &window),
            last_64,
            "only the last 64 bytes count"
        );
        window[69] = 8;
        assert_ne!(hash(&gear, &window), last_64, "the last byte counts");
    }

    #[test]
    fn short_input_is_one_chunk() {
        let gear = gear_table(&[1; 32], &[2; 16]);
        assert_eq!(lengths(&gear, &[]), Vec::<usize>::new());
        assert_eq!(lengths(&gear, &[5; 10]), [10]);
        assert_eq!(lengths(&gear, &vec![5; MIN]), [MIN]);
        // Above the minimum but below the first pair: nothing is tested.
        assert_eq!(lengths(&gear, &vec![5; MIN + 1]), [MIN + 1]);
    }

    #[test]
    fn chunks_stay_within_the_bounds() {
        let gear = gear_table(&[3; 32], &[4; 16]);
        let mut data = vec![0u8; 5 * MAX];
        blake3::Hasher::new_keyed(&[9; 32])
            .finalize_xof()
            .fill(&mut data);
        let lengths = lengths(&gear, &data);
        assert_eq!(lengths.iter().sum::<usize>(), data.len());
        let (_, rest) = lengths.split_last().expect("chunks");
        for len in rest {
            assert!((MIN..=MAX).contains(len), "{len}");
        }
    }

    #[test]
    fn secret_objects_are_cut_at_the_maximum() {
        assert_eq!(fixed_lengths(0), Vec::<usize>::new());
        assert_eq!(fixed_lengths(1), [1]);
        assert_eq!(fixed_lengths(MAX), [MAX]);
        assert_eq!(fixed_lengths(MAX + 1), [MAX, 1]);
        assert_eq!(fixed_lengths(5 * MAX / 2), [MAX, MAX, MAX / 2]);
    }
}
