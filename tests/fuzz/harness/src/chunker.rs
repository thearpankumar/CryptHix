//! Content-defined chunking at full size and at scaled-down sizes (FS-52).
//!
//! The input sets up a file and a reader:
//!
//! | Bytes   | Meaning                                                                      |
//! | ------- | ---------------------------------------------------------------------------- |
//! | 0..3    | the file's length, 24-bit big-endian, at most 2.25 MiB                       |
//! | 3..7    | read sizes, used in turn: `0` interrupts a read, `n` reads `n × 4,099` bytes |
//! | 7..39   | the chunker seed (all zero: `[1; 32]`)                                       |
//! | 39..55  | the vault ID (all zero: `[1; 16]`)                                           |
//! | 55..87  | the data key: the file is its keyed XOF stream, or zeros if it is all zero   |
//! | 87..    | the overlay: XOR-ed onto the whole file, repeated from its start             |
//!
//! Missing bytes count as zero; a length over 2.25 MiB is cut to 2.25 MiB: just over two maximum
//! chunks and the reader's 2 MiB window, so a file still reaches a cut at the maximum twice, a
//! last chunk after it and a refill of the window, while each input runs nearly twice as fast
//! as at 4 MiB. The TV-07 chunking inputs are seeds in this form, so their 2.5, 3 and 8 MiB
//! cases are cut to their first 2.25 MiB here (still two maximum chunks of zeros or of a secret
//! file, and several content-defined cuts of the random data); a `pattern` case is a zero data
//! key with the pattern as the overlay.
//!
//! The format 0 hash is only tested from 64 KiB into a chunk and depends on the 64 bytes before
//! the position tested, so the overlay is repeated over the whole file: every input byte
//! reaches the hash at every cut point, and with a zero data key the file is the overlay
//! repeated, which the fuzzer controls entirely. The overlay is also cut on its own at the
//! scaled-down sizes of 64, 256 and 1,024 bytes, where a read size `n` reads `n` bytes and a few
//! KiB of input reach the minimum, the switch of masks, odd tails and the maximum many times.
//!
//! Every file is cut for both classes. For an ordinary object, the chunks [`Chunks`] cuts in
//! memory must be the chunks [`StreamChunker`] cuts through the reader, and the chunks
//! `fastcdc::v2020::cut_gear` 5.0.0 cuts with the same gear table, which this file rebuilds
//! from `chunker_seed` and the vault ID with the crypto crate's KDF and XOF. For a secret-class
//! object, memory and the reader must both give chunks of the maximum and a shorter last one
//! (FS-52).

use std::io::{self, ErrorKind, Read};

use crypthix_core::blob::ObjectClass;
use crypthix_core::chunk::{Chunks, GearTable, MASK_L, MASK_S, StreamChunker};
use crypthix_core::limits::{AVG_CHUNK, GEAR_TABLE_LEN, MAX_CHUNK, MIN_CHUNK};
use crypthix_crypto::kdf::{self, KdfContext};
use crypthix_crypto::key::{KdfKey, XofKey};
use crypthix_crypto::label::XofKeyLabel;
use crypthix_crypto::mac;
use crypthix_types::id::VaultId;
use fastcdc::v2020::{self, Normalization};

/// The longest file the target cuts: 2.25 MiB, past two maximum chunks and the 2 MiB window.
const MAX_LEN: usize = 9 << 18;

/// The unit of a read size at full size.
const READ_UNIT: usize = 4_099;

/// Where the overlay starts in the input.
const OVERLAY: usize = 87;

/// The chunk sizes, masks and read unit of one pass.
#[derive(Clone, Copy)]
struct Scale {
    min: usize,
    avg: usize,
    max: usize,
    mask_s: u64,
    mask_l: u64,
    read_unit: usize,
    /// Format 0, or the scaled-down sizes of the `scaled_for_fuzzing` constructors.
    full: bool,
}

impl Scale {
    /// Format 0: 64 KiB, 256 KiB and 1 MiB.
    const FULL: Self = Self {
        min: MIN_CHUNK,
        avg: AVG_CHUNK,
        max: MAX_CHUNK,
        mask_s: MASK_S,
        mask_l: MASK_L,
        read_unit: READ_UNIT,
        full: true,
    };

    /// 64, 256 and 1,024 bytes with the level 2 masks fastcdc selects for 256.
    fn scaled() -> Self {
        let (mask_s, mask_l) = v2020::select_masks(256, Normalization::Level2);
        Self {
            min: 64,
            avg: 256,
            max: 1024,
            mask_s,
            mask_l,
            read_unit: 1,
            full: false,
        }
    }
}

/// A reader that returns `data` in pieces of the given sizes, in turn, and interrupts a read
/// where the size is 0; the read after an interrupt always returns data.
struct Choppy<'a> {
    data: &'a [u8],
    sizes: [u8; 4],
    unit: usize,
    turn: usize,
    interrupted: bool,
}

impl Read for Choppy<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.sizes[self.turn % self.sizes.len()];
        self.turn += 1;
        if size == 0 && !self.interrupted {
            self.interrupted = true;
            return Err(ErrorKind::Interrupted.into());
        }
        self.interrupted = false;
        let len = (usize::from(size.max(1)) * self.unit)
            .min(buf.len())
            .min(self.data.len());
        let (head, rest) = self.data.split_at(len);
        buf[..len].copy_from_slice(head);
        self.data = rest;
        Ok(len)
    }
}

/// The `N` bytes of `data` from `start`, with zeros for any past its end.
fn field<const N: usize>(data: &[u8], start: usize) -> [u8; N] {
    std::array::from_fn(|i| data.get(start + i).copied().unwrap_or(0))
}

/// The gear words fastcdc takes: the keyed XOF under
/// `K_gear = KDF(chunker_seed, -, kdf/gear, vault_id)`, as little-endian `u64`s (FS-52).
fn gear_words(seed: &KdfKey, vault_id: &VaultId) -> Vec<u64> {
    let context = KdfContext::new().field(vault_id.as_bytes());
    let key: XofKey = kdf::kdf(seed, None, XofKeyLabel::Gear, &context).expect("derives");
    let mut bytes = [0u8; GEAR_TABLE_LEN];
    mac::xof(&key, &mut bytes);
    let (words, _) = bytes.as_chunks::<8>();
    words.iter().map(|word| u64::from_le_bytes(*word)).collect()
}

/// The chunk lengths of `data` under fastcdc 5.0.0 with `words` at `scale`.
fn fastcdc_lengths(words: &[u64], data: &[u8], scale: Scale) -> Vec<usize> {
    let shifted: Vec<u64> = words.iter().map(|word| word << 1).collect();
    let mut lengths = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let (_, len) = v2020::cut_gear(
            &data[offset..],
            scale.min,
            scale.avg,
            scale.max,
            scale.mask_s,
            scale.mask_l,
            scale.mask_s << 1,
            scale.mask_l << 1,
            words,
            &shifted,
        );
        lengths.push(len);
        offset += len;
    }
    lengths
}

/// Cuts `file` for an object of `class` at `scale` in memory and through a reader, checks that
/// the two agree and that the chunks cover the file within the size bounds, and returns the
/// lengths.
fn cut_both_ways(
    gear: &GearTable,
    class: ObjectClass,
    file: &[u8],
    sizes: [u8; 4],
    scale: Scale,
) -> Vec<usize> {
    let len = file.len();
    let chunks = if scale.full {
        Chunks::new(gear, class, file)
    } else {
        Chunks::scaled_for_fuzzing(gear, class, file)
    };
    let shape = chunks.object_shape();
    let in_memory: Vec<usize> = chunks.map(|range| range.len()).collect();
    assert_eq!(shape.class(), class, "the shape's class");
    assert_eq!(shape.is_single(), in_memory.len() <= 1, "the shape");

    assert_eq!(
        in_memory.iter().sum::<usize>(),
        len,
        "the chunks do not cover the file"
    );
    if let Some((last, rest)) = in_memory.split_last() {
        assert!(
            (1..=scale.max).contains(last),
            "a last chunk of {last} bytes"
        );
        for chunk in rest {
            assert!(
                (scale.min..=scale.max).contains(chunk),
                "a chunk of {chunk} bytes"
            );
        }
    }

    let reader = Choppy {
        data: file,
        sizes,
        unit: scale.read_unit,
        turn: 0,
        interrupted: false,
    };
    let chunker = if scale.full {
        StreamChunker::new(gear, class, reader)
    } else {
        StreamChunker::scaled_for_fuzzing(gear, class, reader)
    };
    let mut chunker = chunker.expect("a window");
    let mut offset = 0;
    let mut streamed = Vec::new();
    while let Some(chunk) = chunker.next_chunk().expect("the reader does not fail") {
        assert_eq!(chunk.index(), streamed.len() as u64, "chunk index");
        assert_eq!(chunk.object_shape(), shape, "the stream's shape");
        let bytes = chunk.bytes();
        assert_eq!(bytes, &file[offset..offset + bytes.len()], "chunk bytes");
        offset += bytes.len();
        assert_eq!(chunk.is_last(), offset == len, "is_last at {offset}");
        streamed.push(bytes.len());
    }
    assert_eq!(
        streamed, in_memory,
        "the stream cuts other chunks than memory"
    );
    in_memory
}

/// Cuts `file` at `scale` for both classes, in memory and through a reader, and the ordinary
/// class with fastcdc too.
fn check(gear: &GearTable, words: &[u64], file: &[u8], sizes: [u8; 4], scale: Scale) {
    let in_memory = cut_both_ways(gear, ObjectClass::Ordinary, file, sizes, scale);
    let secret = cut_both_ways(gear, ObjectClass::Secret, file, sizes, scale);
    let mut fixed = vec![scale.max; file.len() / scale.max];
    if !file.len().is_multiple_of(scale.max) {
        fixed.push(file.len() % scale.max);
    }
    assert_eq!(
        secret, fixed,
        "a secret object is not cut at fixed steps of the maximum"
    );
    assert_eq!(
        fastcdc_lengths(words, file, scale),
        in_memory,
        "fastcdc 5.0.0 cuts other chunks with the same gear table"
    );
}

/// Cuts the file `data` describes in memory, through a reader, and with fastcdc, then the
/// overlay alone at the scaled-down sizes.
///
/// # Panics
///
/// If the three disagree, a chunk other than the last is outside the minimum to the maximum,
/// the stream's chunk indices, `is_last` or shape are wrong, the chunks do not rebuild the file,
/// or a secret-class object is not cut at fixed steps of the maximum.
pub fn chunker(data: &[u8]) {
    let [high, middle, low] = field::<3>(data, 0);
    let len = usize::try_from(u32::from_be_bytes([0, high, middle, low]))
        .expect("24 bits")
        .min(MAX_LEN);
    let sizes = field::<4>(data, 3);
    let mut seed = field::<32>(data, 7);
    if seed == [0; 32] {
        seed = [1; 32];
    }
    let mut vault = field::<16>(data, 39);
    if vault == [0; 16] {
        vault = [1; 16];
    }
    let data_key = field::<32>(data, 55);
    let overlay = data.get(OVERLAY..).unwrap_or_default();

    let mut file = vec![0u8; len];
    if let Ok(key) = XofKey::from_bytes(data_key) {
        mac::xof(&key, &mut file);
    }
    if !overlay.is_empty() {
        for (byte, mask) in file.iter_mut().zip(overlay.iter().cycle()) {
            *byte ^= mask;
        }
    }

    let seed = KdfKey::from_bytes(seed).expect("non-zero seed");
    let vault_id = VaultId::try_from_bytes(vault).expect("non-zero ID");
    let gear = GearTable::derive(&seed, &vault_id).expect("derives");
    let words = gear_words(&seed, &vault_id);
    check(&gear, &words, &file, sizes, Scale::FULL);
    check(&gear, &words, overlay, sizes, Scale::scaled());
}
