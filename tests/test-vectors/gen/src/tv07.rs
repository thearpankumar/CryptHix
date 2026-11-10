//! TV-07: chunking boundaries, Padmé, the inner plaintext, compression, and data and meta blobs
//! (FS-52 to FS-57).
//!
//! Every output comes from this crate's own code: the one-byte-a-time chunker of [`cdc`], the
//! Padmé of [`padme`], the inner plaintexts of [`inner`], hand-built zstd frames and the
//! section 7 primitives of [`cx`]. Only the encoder frames come from zstd itself (`zstd-safe`,
//! the version in the header): they are inputs to decompression, which gives the results FS-53
//! defines through libzstd 1.5.7, and the expected output of the encoder groups, which only the
//! pinned version must match.
//! Inputs too large for hex are given as `dataKey` and `length`, the first `length` bytes of the
//! keyed BLAKE3 XOF under `dataKey` over the empty input, as `pattern` and `length`, the
//! pattern repeated to `length` bytes, or as `zeros`, a run of zero bytes. A frame with a run of
//! more than 1,024 zero bytes is given as `frameHead`, `frameZeros` zero bytes and `frameTail`,
//! and an all-zero expected plaintext of more than 1,024 bytes as `plaintextZeros`, its length.

use crypthix_crypto::test_rng::Stream;

use crate::cdc;
use crate::cx;
use crate::inner::{self, header, padded_len};
use crate::labels;
use crate::padme::padme;
use crate::test_case::{Input, TestCase};
use crate::vector_set::VectorSet;
use crate::zstd_frame::{self, Bent, Block, Header};

/// The seed of the set's streams: `BLAKE3("crypthix-vector-gen TV-07")`.
fn seed() -> [u8; 32] {
    *blake3::hash(b"crypthix-vector-gen TV-07").as_bytes()
}

/// 1 MiB, the cap on `plain_len` and `payload_len` (FS-53, FS-54).
const MIB: usize = 1 << 20;

/// The first `len` bytes of the keyed XOF under `key`.
pub(crate) fn xof(key: &[u8; 32], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    blake3::Hasher::new_keyed(key).finalize_xof().fill(&mut out);
    out
}

/// `len` bytes of the keyed XOF under `key`, from `offset`.
fn xof_at(key: &[u8; 32], offset: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut reader = blake3::Hasher::new_keyed(key).finalize_xof();
    reader.set_position(u64::try_from(offset).expect("small"));
    reader.fill(&mut out);
    out
}

/// Text that compresses well.
fn text(len: usize) -> Vec<u8> {
    b"The quick brown fox jumps over the lazy dog. "
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

/// A large input: a keyed XOF stream, a run of zeros, or a short pattern repeated.
#[derive(Clone, Debug)]
enum Big {
    Stream([u8; 32], usize),
    Zeros(usize),
    Pattern(Vec<u8>, usize),
}

impl Big {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Big::Stream(key, len) => xof(key, *len),
            Big::Zeros(len) => vec![0; *len],
            Big::Pattern(pattern, len) => pattern.iter().copied().cycle().take(*len).collect(),
        }
    }

    fn inputs(&self) -> Vec<(&'static str, Input)> {
        match self {
            Big::Stream(key, len) => vec![
                ("dataKey", Input::bytes(key)),
                ("length", Input::Int(int(*len))),
            ],
            Big::Zeros(len) => vec![("zeros", Input::Int(int(*len)))],
            Big::Pattern(pattern, len) => vec![
                ("pattern", Input::bytes(pattern)),
                ("length", Input::Int(int(*len))),
            ],
        }
    }
}

fn int(value: usize) -> i64 {
    i64::try_from(value).expect("small")
}

fn ints(values: &[usize]) -> Input {
    Input::Ints(values.iter().copied().map(int).collect())
}

// ----------------------------------------------------------------------------------------------
// Chunking (FS-52)

/// How many candidates a search for an edge case tries before it gives up. Each search succeeds
/// with probability about 2^-16 or better per candidate, so the bound is never reached.
const TRIES: u64 = 1 << 24;

/// The length of the repeated pattern that is never cut before the maximum.
const PATTERN_LEN: usize = 1_021;

/// The first candidate key under `base`, `H(base, counter)` for counters from 0, for which
/// `found` gives a value.
fn search<T>(base: &[u8; 32], what: &str, mut found: impl FnMut([u8; 32]) -> Option<T>) -> T {
    (0..TRIES)
        .find_map(|counter| found(*blake3::keyed_hash(base, &counter.to_le_bytes()).as_bytes()))
        .unwrap_or_else(|| panic!("no {what} in {TRIES} tries"))
}

/// The length of the first chunk of `data`.
fn first_cut(gear: &[u64; 256], data: &Big) -> usize {
    cdc::lengths(gear, &data.bytes())
        .first()
        .copied()
        .unwrap_or(0)
}

/// A chunking case found by search: comment, chunker seed, gear table and data.
type Edge = (&'static str, [u8; 32], [u64; 256], Big);

/// Files whose cut points sit exactly on the edges of the FS-52 rule, found by a deterministic
/// search over data keys (and chunker seeds, where the edge depends on one gear word) and
/// checked here with the one-byte chunker, so each case shows what its comment says: a
/// chunker off by one at that edge cuts elsewhere.
#[allow(clippy::too_many_lines, reason = "one search per edge")]
fn chunk_edges(
    seed: &[u8; 32],
    vault_id: &[u8; 16],
    chunker_seed: &[u8; 32],
    gear: &[u64; 256],
) -> Vec<Edge> {
    use cdc::{AVG, MASK_L, MASK_S, MAX, MIN};
    let mut stream = Stream::new(seed, "chunking-edges");
    let bases: [[u8; 32]; 10] = std::array::from_fn(|_| stream.bytes());
    let matches = |hash: u64, mask: u64| hash & mask == 0;
    let mut edges = Vec::new();

    // An odd length MIN + 3: MIN and MIN + 1 are tested under the strict mask, the last byte
    // at MIN + 2 = 2⌊center/2⌋ would be tested under the loose one, and it matches.
    let len = MIN + 3;
    let key = search(&bases[0], "odd last byte that matches", |key| {
        let window = xof_at(&key, MIN, 3);
        let hash = |n: usize| cdc::hash(gear, &window[..n]);
        (!matches(hash(1), MASK_S) && !matches(hash(2), MASK_S) && matches(hash(3), MASK_L))
            .then_some(key)
    });
    let data = Big::Stream(key, len);
    let bytes = data.bytes();
    assert_eq!(len & !1, MIN + 2, "the last byte is past the strict range");
    assert!(matches(cdc::hash(gear, &bytes[MIN..]), MASK_L));
    assert_eq!(
        cdc::lengths(gear, &bytes),
        [len],
        "the odd last byte is not a cut point"
    );
    edges.push((
        "an odd last byte whose hash matches the mask is never tested: one chunk",
        *chunker_seed,
        *gear,
        data,
    ));

    // A cut at MIN: the hash there is one gear word, so first find a table with a word that
    // matches the strict mask, then a file with that byte at MIN.
    let (min_seed, min_gear, value) = search(&bases[1], "gear word that matches", |seed| {
        let gear = cdc::gear_table(&seed, vault_id);
        let value = (0..=u8::MAX).find(|byte| matches(gear[usize::from(*byte)], MASK_S))?;
        Some((seed, gear, value))
    });
    let key = search(&bases[2], "file with that byte at the minimum", |key| {
        (xof_at(&key, MIN, 1)[0] == value).then_some(key)
    });
    let data = Big::Stream(key, 3 * MIN);
    assert_eq!(first_cut(&min_gear, &data), MIN, "a cut at the minimum");
    edges.push((
        "a cut at exactly the 64 KiB minimum, the first position tested",
        min_seed,
        min_gear,
        data,
    ));

    // A cut at MIN + 1, from a pair of bytes whose first does not match.
    let (pair_seed, pair_gear, pairs) = search(&bases[3], "pair of bytes that match", |seed| {
        let gear = cdc::gear_table(&seed, vault_id);
        let pairs: Vec<[u8; 2]> = (0..=u16::MAX)
            .map(u16::to_be_bytes)
            .filter(|pair| {
                !matches(cdc::hash(&gear, &pair[..1]), MASK_S)
                    && matches(cdc::hash(&gear, pair), MASK_S)
            })
            .collect();
        (!pairs.is_empty()).then_some((seed, gear, pairs))
    });
    let key = search(&bases[4], "file with that pair at the minimum", |key| {
        let window = xof_at(&key, MIN, 2);
        pairs.contains(&[window[0], window[1]]).then_some(key)
    });
    let data = Big::Stream(key, 3 * MIN);
    assert_eq!(
        first_cut(&pair_gear, &data),
        MIN + 1,
        "a cut one past the minimum"
    );
    edges.push((
        "a cut at the minimum plus one, the second byte of the first pair",
        pair_seed,
        pair_gear,
        data,
    ));

    // Longer than AVG, so center = AVG and the loose mask starts at AVG. The hash at a position
    // depends on the 64 bytes up to it only.
    let len = 3 * AVG;
    let loose_only = |hash: u64| matches(hash, MASK_L) && !matches(hash, MASK_S);
    let key = search(&bases[5], "loose-only match at the average", |key| {
        let hash = cdc::hash(gear, &xof_at(&key, AVG - 63, 64));
        (loose_only(hash) && first_cut(gear, &Big::Stream(key, len)) == AVG).then_some(key)
    });
    edges.push((
        "a cut at 256 KiB, the first position under the loose mask; the strict mask does not match there",
        *chunker_seed,
        *gear,
        Big::Stream(key, len),
    ));
    let key = search(&bases[6], "loose-only match before the average", |key| {
        let hash = cdc::hash(gear, &xof_at(&key, AVG - 64, 64));
        (loose_only(hash) && first_cut(gear, &Big::Stream(key, len)) > AVG - 1).then_some(key)
    });
    edges.push((
        "the loose mask would match at 256 KiB - 1, the last position under the strict mask: no cut there",
        *chunker_seed,
        *gear,
        Big::Stream(key, len),
    ));

    // Shorter than AVG: center = len, every tested position is strict, and the last one tested
    // is strict_end - 1 = 2⌊len/2⌋ - 1. Find a file whose first strict match is at an odd
    // position p, and cut the file to p + 1 bytes.
    let (key, cut) = search(&bases[7], "strict match at an odd position", |key| {
        let cut = first_cut(gear, &Big::Stream(key, AVG));
        (cut < AVG && cut % 2 == 1).then_some((key, cut))
    });
    let data = Big::Stream(key, cut + 1);
    let bytes = data.bytes();
    let window = &bytes[cut.saturating_sub(63).max(MIN)..=cut];
    assert!(
        matches(cdc::hash(gear, window), MASK_S),
        "a strict match at {cut}"
    );
    assert_eq!(
        cdc::lengths(gear, &bytes),
        [cut, 1],
        "a cut at strict_end - 1"
    );
    edges.push((
        "a strict match at 2⌊n/2⌋ − 1, the last position tested: a one-byte last chunk",
        *chunker_seed,
        *gear,
        data,
    ));

    // A pattern repeated: the hash takes PATTERN_LEN values, so a pattern none of whose values
    // matches the loose mask (or the strict one, which has every bit of the loose) is never cut
    // before the maximum.
    let len = 2 * MAX + 5;
    let pattern = search(&bases[8], "pattern that never matches", |key| {
        let pattern = xof(&key, PATTERN_LEN);
        let data = Big::Pattern(pattern.clone(), len);
        (cdc::lengths(gear, &data.bytes()) == [MAX, MAX, 5]).then_some(pattern)
    });
    edges.push((
        "a 1,021-byte random pattern repeated over 2 MiB + 5 bytes: no position matches, cut at the 1 MiB maximum",
        *chunker_seed,
        *gear,
        Big::Pattern(pattern, len),
    ));

    // Longer than AVG and shorter than MAX, so both masks are used and end = n, with no
    // position matching either: the whole file is one chunk. Checked here position by
    // position from the hash of the window before it, not only through the chunker.
    let len = AVG + MIN;
    let key = search(&bases[9], "file with no match below its length", |key| {
        (cdc::lengths(gear, &xof(&key, len)) == [len]).then_some(key)
    });
    let bytes = xof(&key, len);
    for position in MIN..(len & !1) {
        let mask = if position < AVG { MASK_S } else { MASK_L };
        let window = &bytes[position.saturating_sub(63).max(MIN)..=position];
        assert!(
            !matches(cdc::hash(gear, window), mask),
            "a match at {position}"
        );
    }
    edges.push((
        "320 KiB with no position matching under either mask: one chunk of the whole file, shorter than the maximum",
        *chunker_seed,
        *gear,
        Big::Stream(key, len),
    ));
    edges
}

fn chunking_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "chunking");
    let chunker_seed: [u8; 32] = stream.bytes();
    let other_seed: [u8; 32] = stream.bytes();
    let vault_id: [u8; 16] = stream.bytes();
    let data_key: [u8; 32] = stream.bytes();
    let gear = cdc::gear_table(&chunker_seed, &vault_id);
    let other_gear = cdc::gear_table(&other_seed, &vault_id);

    let big = Big::Stream(data_key, 8 * MIB);
    let with_lengths = |comment: &'static str,
                        flag: &'static str,
                        chunker_seed: &[u8; 32],
                        class: &'static str,
                        data: Big,
                        lengths: &[usize]| {
        let mut inputs = vec![
            ("chunkerSeed", Input::bytes(chunker_seed)),
            ("vaultId", Input::bytes(&vault_id)),
            ("class", Input::text(class)),
        ];
        inputs.extend(data.inputs());
        TestCase::new(comment, &[flag], "Ok", inputs).with_outputs(vec![("lengths", ints(lengths))])
    };
    let case = |comment: &'static str,
                flag: &'static str,
                chunker_seed: &[u8; 32],
                gear: &[u64; 256],
                data: Big| {
        let lengths = cdc::lengths(gear, &data.bytes());
        with_lengths(comment, flag, chunker_seed, "ordinary", data, &lengths)
    };
    // A secret-class object is cut from its length alone, never through the gear table.
    let secret = |comment: &'static str, data: Big| {
        let len = data.bytes().len();
        let lengths = cdc::fixed_lengths(len);
        with_lengths(
            comment,
            "SecretFixed",
            &chunker_seed,
            "secret",
            data,
            &lengths,
        )
    };
    // An odd tail of MIN + 3 bytes after the first boundary past 1 MiB: positions MIN and
    // MIN + 1 are tested, the last byte is not. The earlier boundaries stay where they were.
    let prefix = xof(&data_key, 3 * MIB);
    let boundary: usize = cdc::lengths(&gear, &prefix)
        .iter()
        .scan(0, |end, len| {
            *end += len;
            Some(*end)
        })
        .find(|end| *end > MIB)
        .expect("a boundary past 1 MiB");
    let odd = Big::Stream(data_key, boundary + cdc::MIN + 3);
    let odd_lengths = cdc::lengths(&gear, &odd.bytes());
    assert_eq!(odd_lengths.last(), Some(&(cdc::MIN + 3)), "an odd tail");
    let main_lengths = cdc::lengths(&gear, &big.bytes());
    assert_ne!(
        main_lengths,
        cdc::lengths(&other_gear, &big.bytes()),
        "another chunker seed moves the boundaries"
    );
    let s = &chunker_seed;
    let g = &gear;
    #[rustfmt::skip]
    let mut tests = vec![
        case("an empty file has no chunks", "SmallFile", s, g, Big::Zeros(0)),
        case("one byte is one chunk", "SmallFile", s, g, Big::Stream(data_key, 1)),
        case("one byte under the 64 KiB minimum", "SmallFile", s, g, Big::Stream(data_key, cdc::MIN - 1)),
        case("exactly the minimum is one chunk", "SmallFile", s, g, Big::Stream(data_key, cdc::MIN)),
        case("one byte over the minimum: no position is tested", "CutPoints", s, g, Big::Stream(data_key, cdc::MIN + 1)),
        case("3 MiB of zeros", "CutPoints", s, g, Big::Zeros(3 * MIB)),
        case("an odd tail of 64 KiB + 3 bytes after a boundary: the last byte is never a cut point", "CutPoints", s, g, odd),
        case("8 MiB of random data", "CutPoints", s, g, big.clone()),
        case("the same 8 MiB under another chunker seed", "KeyedGear", &other_seed, &other_gear, big.clone()),
        secret("an empty secret file has no chunks", Big::Zeros(0)),
        secret("a secret file of exactly 1 MiB is one chunk", Big::Stream(data_key, MIB)),
        secret("a secret file of 1 MiB and one byte is two chunks", Big::Stream(data_key, MIB + 1)),
        secret("2.5 MiB of a secret file: 1 MiB, 1 MiB, 0.5 MiB", Big::Stream(data_key, 5 * MIB / 2)),
        secret("the 8 MiB of random data in a secret file: eight 1 MiB chunks", big),
    ];
    for (comment, edge_seed, edge_gear, data) in chunk_edges(seed, &vault_id, &chunker_seed, &gear)
    {
        tests.push(case(comment, "CutEdges", &edge_seed, &edge_gear, data));
    }
    tests
}

// ----------------------------------------------------------------------------------------------
// Padmé (FS-54)

fn padme_tests() -> Vec<TestCase> {
    let lengths: [(&'static str, u64); 12] = [
        ("0 stays 0", 0),
        ("1 stays 1", 1),
        ("2 stays 2", 2),
        ("7 stays 7", 7),
        ("9 rounds to 10", 9),
        ("an empty payload: 6", 6),
        ("a 1,000-byte payload: 1,006", 1_006),
        ("1,025 rounds to a multiple of 64", 1_025),
        ("a 64 KiB chunk: 65,542", 65_542),
        ("2^20 stays 2^20", 1 << 20),
        ("a 1 MiB payload: 2^20 + 6", (1 << 20) + 6),
        ("2^32 + 1", (1 << 32) + 1),
    ];
    lengths
        .into_iter()
        .map(|(comment, len)| {
            let value = i64::try_from(len).expect("small");
            let padded = i64::try_from(padme(len)).expect("small");
            TestCase::new(
                comment,
                &["Padme"],
                "Ok",
                vec![("length", Input::Int(value))],
            )
            .with_outputs(vec![("padded", Input::Int(padded))])
        })
        .collect()
}

// ----------------------------------------------------------------------------------------------
// Inner plaintext (FS-54)

fn inner_case(
    comment: &'static str,
    flag: &'static str,
    expect: &'static str,
    bytes: &[u8],
) -> TestCase {
    let ok = expect == "Ok";
    let test = TestCase::new(
        comment,
        &[flag],
        expect,
        vec![("inner", Input::bytes(bytes))],
    );
    if !ok {
        return test;
    }
    let len = u32::from_be_bytes(bytes[2..6].try_into().expect("4 bytes"));
    let len = usize::try_from(len).expect("small");
    test.with_outputs(vec![
        ("comp", Input::Int(i64::from(bytes[0]))),
        ("payload", Input::bytes(&bytes[6..6 + len])),
    ])
}

/// `bytes` with `byte` at `index` set to `value`.
fn with(bytes: &[u8], index: usize, value: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[index] = value;
    out
}

fn inner_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "inner");
    let payload_key: [u8; 32] = stream.bytes();
    let mut payload = vec![0u8; 1_000];
    stream.fill_bytes(&mut payload);
    let thousand = inner::inner(0, &payload);
    assert_eq!(thousand.len(), 1_024);
    let longer = [thousand.as_slice(), &[0]].concat();
    let cap = u32::try_from(MIB).expect("small");

    // The 1 MiB payload is too large for hex: header, stream and pad are given apart.
    let full = TestCase::new(
        "a payload of exactly 1 MiB",
        &["InnerLimit"],
        "Ok",
        vec![
            ("header", Input::Bytes(header(0, 0, cap))),
            ("dataKey", Input::bytes(&payload_key)),
            ("length", Input::Int(int(MIB))),
            ("padLength", Input::Int(int(padded_len(MIB) - MIB - 6))),
        ],
    )
    .with_outputs(vec![("comp", Input::Int(0))]);

    #[rustfmt::skip]
    let tests = vec![
        inner_case("an empty raw payload is the 6-byte header", "InnerOk", "Ok", &inner::inner(0, b"")),
        inner_case("a 3-byte zstd payload, padded to 10", "InnerOk", "Ok", &inner::inner(1, b"abc")),
        inner_case("a 1,000-byte raw payload, padded to 1,024", "InnerOk", "Ok", &thousand),
        full,
        inner_case("payload_len 2^20 + 1", "InnerLimit", "Limit", &header(0, 0, cap + 1)),
        inner_case("payload_len 2^32 - 1", "InnerLimit", "Limit", &header(1, 0, u32::MAX)),
        inner_case("payload_len 2^20 with only the header", "InnerPadding", "Padding", &header(0, 0, cap)),
        inner_case("no bytes", "InnerPadding", "Padding", &[]),
        inner_case("five bytes, one short of a header", "InnerPadding", "Padding", &[0; 5]),
        inner_case("comp 2", "InnerPadding", "Padding", &with(&thousand, 0, 2)),
        inner_case("comp 255", "InnerPadding", "Padding", &with(&thousand, 0, 0xff)),
        inner_case("rsv 1", "InnerPadding", "Padding", &with(&thousand, 1, 1)),
        inner_case("rsv 0x80", "InnerPadding", "Padding", &with(&thousand, 1, 0x80)),
        inner_case("the first pad byte is not zero", "InnerPadding", "Padding", &with(&thousand, 1_006, 1)),
        inner_case("the last pad byte is not zero", "InnerPadding", "Padding", &with(&thousand, 1_023, 0x80)),
        inner_case("one byte longer than padme(6 + payload_len)", "InnerPadding", "Padding", &longer),
        inner_case("one byte shorter than padme(6 + payload_len)", "InnerPadding", "Padding", &thousand[..1_023]),
        inner_case("no pad at all", "InnerPadding", "Padding", &thousand[..1_006]),
        inner_case("comp 2 with payload_len 2^20 + 1: comp is checked first", "CheckOrder", "Padding", &header(2, 0, cap + 1)),
        inner_case("rsv 1 with payload_len 2^20 + 1: rsv is checked first", "CheckOrder", "Padding", &header(0, 1, cap + 1)),
    ];
    tests
}

// ----------------------------------------------------------------------------------------------
// Compression (FS-53): the encoder under the pinned version

/// The class names the vectors use.
const ORDINARY: &str = "ordinary";
const SECRET: &str = "secret";

/// The inner plaintext FS-53 writes for `chunk`.
fn encode_chunk(chunk: &[u8], class: &str) -> Vec<u8> {
    if class == SECRET {
        return inner::inner(0, chunk);
    }
    let frame = zstd_frame::encode(chunk, Bent::No);
    // Kept only if 16 × frame ≤ 15 × chunk.
    if frame.len() * 16 <= chunk.len() * 15 {
        inner::inner(1, &frame)
    } else {
        inner::inner(0, chunk)
    }
}

/// Raw inner plaintexts above this size are given by their length only: they are the chunk
/// itself with the header and a zero pad.
const HEX_INNER_UP_TO: usize = 16 * 1024;

fn compress_case(
    comment: &'static str,
    flag: &'static str,
    class: &'static str,
    chunk: &Chunk,
) -> TestCase {
    let bytes = chunk.bytes();
    let inner = encode_chunk(&bytes, class);
    let mut inputs = vec![("class", Input::text(class))];
    inputs.extend(chunk.inputs());
    let mut outputs = vec![
        ("comp", Input::Int(i64::from(inner[0]))),
        ("innerLength", Input::Int(int(inner.len()))),
    ];
    if inner.len() <= HEX_INNER_UP_TO {
        outputs.push(("inner", Input::Bytes(inner)));
    }
    TestCase::new(comment, &[flag], "Ok", inputs).with_outputs(outputs)
}

/// A chunk: hex if small, else a large input.
#[derive(Clone, Debug)]
enum Chunk {
    Hex(Vec<u8>),
    Big(Big),
}

impl Chunk {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Chunk::Hex(bytes) => bytes.clone(),
            Chunk::Big(big) => big.bytes(),
        }
    }

    fn inputs(&self) -> Vec<(&'static str, Input)> {
        match self {
            Chunk::Hex(bytes) => vec![("chunk", Input::Bytes(bytes.clone()))],
            Chunk::Big(big) => big.inputs(),
        }
    }
}

/// Two 4,096-byte chunks of random bytes then zeros, one random byte apart, the first kept
/// compressed and the second stored raw.
fn keep_edge(key: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    const LEN: usize = 4_096;
    let random = xof(key, LEN);
    let chunk = |len: usize| [&random[..len], &vec![0; LEN - len]].concat();
    let kept = |data: &[u8]| zstd_frame::encode(data, Bent::No).len() * 16 <= LEN * 15;
    // Bisect between all zeros, which is kept, and all random, which is not.
    let (mut low, mut high) = (0, LEN);
    assert!(kept(&chunk(low)) && !kept(&chunk(high)));
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if kept(&chunk(middle)) {
            low = middle;
        } else {
            high = middle;
        }
    }
    let (below, at) = (chunk(low), chunk(high));
    (below, at)
}

fn compress_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "compress");
    let random_key: [u8; 32] = stream.bytes();
    let edge_key: [u8; 32] = stream.bytes();
    let mut random = vec![0u8; 100];
    stream.fill_bytes(&mut random);
    let (kept, raw) = keep_edge(&edge_key);
    let zeros = || Chunk::Big(Big::Zeros(MIB));
    #[rustfmt::skip]
    let tests = vec![
        compress_case("1 MiB of zeros", "Compress", ORDINARY, &zeros()),
        compress_case("5,000 bytes of text", "Compress", ORDINARY, &Chunk::Hex(text(5_000))),
        compress_case("random bytes then zeros: the frame just saves 1/16", "StoreRaw", ORDINARY, &Chunk::Hex(kept)),
        compress_case("one more random byte: the frame no longer saves 1/16, stored raw", "StoreRaw", ORDINARY, &Chunk::Hex(raw)),
        compress_case("100 random bytes are stored raw", "StoreRaw", ORDINARY, &Chunk::Hex(random)),
        compress_case("an empty chunk is stored raw", "StoreRaw", ORDINARY, &Chunk::Hex(Vec::new())),
        compress_case("1 MiB of random data is stored raw", "StoreRaw", ORDINARY, &Chunk::Big(Big::Stream(random_key, MIB))),
        compress_case("a secret object's text is never compressed", "SecretRaw", SECRET, &Chunk::Hex(text(5_000))),
        compress_case("a secret object's 1 MiB of zeros is never compressed", "SecretRaw", SECRET, &zeros()),
    ];
    tests
}

// ----------------------------------------------------------------------------------------------
// Decompression (FS-53): any zstd version

fn frame_case(
    comment: &'static str,
    flag: &'static str,
    frame: Vec<u8>,
    plain_len: usize,
    plaintext: Option<&[u8]>,
) -> TestCase {
    let expect = if plaintext.is_some() {
        "Ok"
    } else {
        "Decompress"
    };
    let mut inputs = match longest_zero_run(&frame) {
        (start, len) if len > 1_024 => vec![
            ("frameHead", Input::bytes(&frame[..start])),
            ("frameZeros", Input::Int(int(len))),
            ("frameTail", Input::bytes(&frame[start + len..])),
        ],
        _ => vec![("frame", Input::Bytes(frame))],
    };
    inputs.push(("plainLen", Input::Int(int(plain_len))));
    let test = TestCase::new(comment, &[flag], expect, inputs);
    match plaintext {
        Some(plaintext) if plaintext.iter().all(|byte| *byte == 0) && plaintext.len() > 1_024 => {
            test.with_outputs(vec![("plaintextZeros", Input::Int(int(plaintext.len())))])
        }
        Some(plaintext) => test.with_outputs(vec![("plaintext", Input::bytes(plaintext))]),
        None => test,
    }
}

/// The start and length of the first longest run of zero bytes in `bytes`.
fn longest_zero_run(bytes: &[u8]) -> (usize, usize) {
    let mut best = (0, 0);
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != 0 {
            start = index + 1;
        } else if index + 1 - start > best.1 {
            best = (start, index + 1 - start);
        }
    }
    best
}

/// A decompression case: comment, flag, frame, `plain_len` and the plaintext if it decodes.
type FrameCase = (&'static str, &'static str, Vec<u8>, usize, Option<Vec<u8>>);

fn decompress_tests() -> Vec<TestCase> {
    let words = text(3_000);
    let encoded = zstd_frame::encode(&words, Bent::No);
    let hello = zstd_frame::raw_frame(b"hello");
    let declared = |size: u64, content: &[u8]| {
        zstd_frame::frame(&Header::declaring(size), &[Block::Raw(content.to_vec())])
    };
    let windowed = |window: u8| {
        let header = Header {
            single_segment: false,
            window,
            ..Header::declaring(5)
        };
        zstd_frame::frame(&header, &[Block::Raw(b"hello".to_vec())])
    };
    let bent = |change: fn(&mut Header)| {
        let mut header = Header::declaring(5);
        change(&mut header);
        zstd_frame::frame(&header, &[Block::Raw(b"hello".to_vec())])
    };
    let skippable = zstd_frame::skippable(b"skip");
    let rle = zstd_frame::rle_frame(b'a', 300);
    let rle_head = rle.clone();
    let wide_rle = zstd_frame::frame(
        &Header {
            fcs_flag: Some(2),
            ..Header::declaring(300)
        },
        &[Block::Rle(b'a', 300)],
    );
    let zeros = vec![0u8; MIB];
    let one_over = zstd_frame::rle_frame(0, MIB + 1);
    let mut wrong_magic = hello.clone();
    wrong_magic[0] ^= 1;
    let ok = |plaintext: &[u8]| Some(plaintext.to_vec());
    let w20 = Header::window_of(20);
    let reserved = zstd_frame::frame(&Header::declaring(5), &[Block::Reserved(b"hello".to_vec())]);
    let block_zeros = vec![0u8; zstd_frame::MAX_BLOCK];
    let max_block = zstd_frame::raw_frame(&block_zeros);
    let over_block = vec![0u8; zstd_frame::MAX_BLOCK + 1];
    let rle_longer = zstd_frame::frame(&Header::declaring(5), &[Block::Rle(b'a', 6)]);

    #[rustfmt::skip]
    let cases: Vec<FrameCase> = vec![
        ("an encoder frame of 3,000 bytes of text", "FrameOk", encoded.clone(), 3_000, ok(&words)),
        ("a raw block of 5 bytes, one-byte content size", "FrameOk", hello.clone(), 5, ok(b"hello")),
        ("an empty raw block, content size 0", "FrameOk", zstd_frame::raw_frame(b""), 0, ok(b"")),
        ("an RLE block of 300 bytes, two-byte content size", "FrameOk", rle, 300, ok(&[b'a'; 300])),
        ("a raw block of exactly 128 KiB, the largest block", "FrameOk", max_block, zstd_frame::MAX_BLOCK, ok(&block_zeros)),
        ("a compressed block of exactly 128 KiB (raw literals, no sequences), then a raw block of 4 bytes", "FrameOk", zstd_frame::max_compressed_block(), zstd_frame::MAX_BLOCK, ok(&block_zeros)),
        ("plain_len 2^20: eight RLE blocks of zeros", "PlainLenCap", zstd_frame::rle_frame(0, MIB), MIB, ok(&zeros)),
        ("plain_len 2^20 + 1 is refused before decoding", "PlainLenCap", one_over, MIB + 1, None),
        ("plain_len one below the declared size", "FrameRejected", hello.clone(), 4, None),
        ("plain_len one above the declared size", "FrameRejected", hello.clone(), 6, None),
        ("the frame holds more than it declares", "FrameRejected", declared(5, b"hello!"), 5, None),
        ("the frame holds less than it declares", "FrameRejected", declared(5, b"hell"), 5, None),
        ("a valid header, then a block of the reserved type 3", "FrameRejected", reserved, 5, None),
        ("an encoder frame with a content checksum", "FrameRejected", zstd_frame::encode(&words, Bent::Checksum), 3_000, None),
        ("an encoder frame without a content size", "FrameRejected", zstd_frame::encode(&words, Bent::NoContentSize), 3_000, None),
        ("a dictionary ID", "FrameRejected", bent(|header| header.dict_id = Some(1)), 5, None),
        ("the reserved bit set", "FrameRejected", bent(|header| header.stray_bits = zstd_frame::RESERVED_BIT), 5, None),
        ("the unused bit set, which libzstd ignores", "FrameRejected", bent(|header| header.stray_bits = zstd_frame::UNUSED_BIT), 5, None),
        ("a four-byte content size for 5 bytes, which libzstd reads", "FrameRejected", bent(|header| header.fcs_flag = Some(2)), 5, None),
        ("an eight-byte content size for 5 bytes, which libzstd reads", "FrameRejected", bent(|header| header.fcs_flag = Some(3)), 5, None),
        ("a four-byte content size for 300 bytes, which libzstd reads", "FrameRejected", wide_rle, 300, None),
        ("a window descriptor of 2^20 bytes instead of a single segment, which libzstd decodes", "FrameRejected", windowed(w20), 5, None),
        ("a window descriptor of 2^21 bytes", "FrameRejected", windowed(Header::window_of(21)), 5, None),
        ("one RLE block of 2^20 zeros, over the 128 KiB block maximum, which libzstd decodes in one pass", "BlockSize", zstd_frame::one_rle_block(MIB), MIB, None),
        ("one raw block of 128 KiB + 1 bytes, which libzstd decodes in one pass", "BlockSize", zstd_frame::raw_frame_one_block(&over_block), zstd_frame::MAX_BLOCK + 1, None),
        ("an RLE block of 6 bytes in a frame of 5, larger than the window", "BlockSize", rle_longer, 5, None),
        ("a skippable frame alone", "FrameRejected", skippable.clone(), 0, None),
        ("a skippable frame before the frame", "FrameRejected", [skippable.as_slice(), &hello].concat(), 5, None),
        ("a skippable frame after the frame", "FrameRejected", [hello.as_slice(), &skippable].concat(), 5, None),
        ("two frames", "FrameRejected", [zstd_frame::raw_frame(&b"hello"[..3]), zstd_frame::raw_frame(&b"hello"[3..])].concat(), 3, None),
        ("a trailing byte", "FrameRejected", [hello.as_slice(), &[0]].concat(), 5, None),
        ("the last byte cut off", "FrameRejected", hello[..hello.len() - 1].to_vec(), 5, None),
        ("the magic number and the descriptor only", "FrameRejected", hello[..5].to_vec(), 5, None),
        ("a two-byte content size cut off after its first byte", "FrameRejected", rle_head[..6].to_vec(), 300, None),
        ("a block header cut off after two bytes", "FrameRejected", hello[..8].to_vec(), 5, None),
        ("a wrong magic number", "FrameRejected", wrong_magic, 5, None),
        ("no bytes", "FrameRejected", Vec::new(), 0, None),
    ];
    cases
        .into_iter()
        .map(|(comment, flag, frame, plain_len, plaintext)| {
            frame_case(comment, flag, frame, plain_len, plaintext.as_deref())
        })
        .collect()
}

// ----------------------------------------------------------------------------------------------
// Data blobs (FS-55, FS-56)

/// The keys and context of one object's data blobs.
struct DataContext {
    dek: [u8; 32],
    dek_salt: [u8; 32],
    vault_id: [u8; 16],
    object_id: [u8; 16],
    dek_id: [u8; 16],
}

impl DataContext {
    fn draw(stream: &mut Stream) -> Self {
        Self {
            dek: stream.bytes(),
            dek_salt: stream.bytes(),
            vault_id: stream.bytes(),
            object_id: stream.bytes(),
            dek_id: stream.bytes(),
        }
    }

    fn context(&self) -> Vec<u8> {
        [&self.vault_id[..], &self.object_id, &self.dek_id].concat()
    }

    /// `K_chunk` (FS-38).
    fn chunk_key(&self) -> [u8; 32] {
        let label = labels::full("kdf", "chunk-key");
        cx::kdf(&self.dek, Some(&self.dek_salt), label, &self.context())
    }

    /// `K_blobid` (FS-38).
    fn blob_id_key(&self) -> [u8; 32] {
        let label = labels::full("kdf", "blob-id-key");
        cx::kdf(&self.dek, Some(&self.dek_salt), label, &self.context())
    }

    /// The keyed blob ID of `chunk` (FS-55).
    fn keyed_id(&self, chunk: &[u8]) -> [u8; 32] {
        cx::mac(&self.blob_id_key(), chunk)
    }

    /// The data-blob AAD with these fields (FS-55).
    fn aad(&self, blob_id: &[u8; 32]) -> Vec<u8> {
        data_aad(&self.vault_id, 0x01, &self.object_id, &self.dek_id, blob_id)
    }

    fn inputs(&self) -> Vec<(&'static str, Input)> {
        vec![
            ("dek", Input::bytes(&self.dek)),
            ("dekSalt", Input::bytes(&self.dek_salt)),
            ("vaultId", Input::bytes(&self.vault_id)),
            ("objectId", Input::bytes(&self.object_id)),
            ("dekId", Input::bytes(&self.dek_id)),
        ]
    }
}

fn data_aad(
    vault_id: &[u8; 16],
    kind: u8,
    object_id: &[u8; 16],
    dek_id: &[u8; 16],
    blob_id: &[u8; 32],
) -> Vec<u8> {
    cx::aad(
        labels::full("aad", "blob-data"),
        &[vault_id, &[kind], object_id, dek_id, blob_id],
    )
}

fn data_seal_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "data-blob-seal");
    let object = DataContext::draw(&mut stream);
    let mut random = vec![0u8; 500];
    stream.fill_bytes(&mut random);
    let random_ids: [[u8; 32]; 2] = [stream.bytes(), stream.bytes()];
    let rands: [[u8; 32]; 4] = std::array::from_fn(|_| stream.bytes());

    let case = |comment: &'static str,
                flags: &[&'static str],
                class: &'static str,
                count: usize,
                chunk: Vec<u8>,
                given_id: Option<[u8; 32]>,
                rand: &[u8; 32]| {
        let blob_id = given_id.unwrap_or_else(|| object.keyed_id(&chunk));
        let inner = encode_chunk(&chunk, class);
        let aad = object.aad(&blob_id);
        let key = object.chunk_key();
        let nonce = cx::hedged_nonce(&key, &aad, &inner, rand);
        let mut inputs = object.inputs();
        inputs.extend([
            ("class", Input::text(class)),
            ("chunkCount", Input::Int(int(count))),
            ("chunk", Input::Bytes(chunk)),
        ]);
        if let Some(id) = given_id {
            inputs.push(("blobId", Input::bytes(&id)));
        }
        inputs.push(("rand", Input::bytes(rand)));
        TestCase::new(comment, flags, "Ok", inputs).with_outputs(vec![
            ("blobId", Input::bytes(&blob_id)),
            ("inner", Input::bytes(&inner)),
            ("nonce", Input::bytes(&nonce)),
            ("sealed", Input::Bytes(cx::seal(&key, &aad, &inner, &nonce))),
        ])
    };
    #[rustfmt::skip]
    let tests = vec![
        case("chunk of a two-chunk object, compressed", &["DataBlobSeal", "KeyedBlobId"], ORDINARY, 2, text(2_000), None, &rands[0]),
        case("random chunk of a three-chunk object, stored raw", &["DataBlobSeal", "KeyedBlobId"], ORDINARY, 3, random, None, &rands[1]),
        case("the one chunk of a single-chunk object", &["DataBlobSeal", "RandomBlobId"], ORDINARY, 1, text(1_500), Some(random_ids[0]), &rands[2]),
        case("chunk of a secret object: raw and a random ID", &["DataBlobSeal", "RandomBlobId", "SecretRaw"], SECRET, 5, text(2_000), Some(random_ids[1]), &rands[3]),
    ];
    tests
}

/// One data-blob open test.
struct Open<'a> {
    object: &'a DataContext,
    class: &'static str,
    count: usize,
    blob_id: [u8; 32],
    plain_len: usize,
    sealed: Vec<u8>,
}

impl Open<'_> {
    fn case(
        self,
        comment: &'static str,
        flags: &[&'static str],
        expect: &'static str,
        plaintext: Option<&[u8]>,
    ) -> TestCase {
        let mut inputs = self.object.inputs();
        inputs.extend([
            ("class", Input::text(self.class)),
            ("chunkCount", Input::Int(int(self.count))),
            ("blobId", Input::bytes(&self.blob_id)),
            ("plainLen", Input::Int(int(self.plain_len))),
            ("sealed", Input::Bytes(self.sealed)),
        ]);
        let test = TestCase::new(comment, flags, expect, inputs);
        match plaintext {
            Some(plaintext)
                if plaintext.iter().all(|byte| *byte == 0) && plaintext.len() > 1_024 =>
            {
                test.with_outputs(vec![("plaintextZeros", Input::Int(int(plaintext.len())))])
            }
            Some(plaintext) => test.with_outputs(vec![("plaintext", Input::bytes(plaintext))]),
            None => test,
        }
    }
}

#[allow(clippy::too_many_lines, reason = "one table of cases")]
fn data_open_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "data-blob-open");
    let object = DataContext::draw(&mut stream);
    let other: [u8; 32] = stream.bytes();
    let other_16: [u8; 16] = stream.bytes();
    let random_id: [u8; 32] = stream.bytes();
    let nonce: [u8; 24] = stream.bytes();
    let mut random = vec![0u8; 300];
    stream.fill_bytes(&mut random);
    let chunk = text(2_000);
    let key = object.chunk_key();
    let id = object.keyed_id(&chunk);
    let compressed = encode_chunk(&chunk, ORDINARY);
    assert_eq!(compressed[0], 1, "text is compressed");
    let frame = zstd_frame::encode(&chunk, Bent::No);
    let raw = inner::inner(0, &chunk);

    // Seals `inner` with the object's own key under the AAD for `blob_id`.
    let seal =
        |blob_id: &[u8; 32], inner: &[u8]| cx::seal(&key, &object.aad(blob_id), inner, &nonce);
    let open = |class, count, blob_id: [u8; 32], plain_len, sealed| Open {
        object: &object,
        class,
        count,
        blob_id,
        plain_len,
        sealed,
    };
    // A keyed chunk of a two-chunk object whose inner plaintext is `inner`.
    let keyed = |inner: &[u8]| open(ORDINARY, 2, id, chunk.len(), seal(&id, inner));
    let good = seal(&id, &compressed);
    let with_aad = |aad: Vec<u8>| {
        open(
            ORDINARY,
            2,
            id,
            chunk.len(),
            cx::seal(&key, &aad, &compressed, &nonce),
        )
    };
    let o = &object;

    let mut longer = raw.clone();
    longer.push(0);
    let mut bad_pad = raw.clone();
    let last = bad_pad.len() - 1;
    bad_pad[last] = 1;
    let checksum = inner::inner(1, &zstd_frame::encode(&chunk, Bent::Checksum));
    let over_declared = inner::inner(
        1,
        &zstd_frame::frame(&Header::declaring(10), &[Block::Raw(chunk[..11].to_vec())]),
    );
    let other_id = object.keyed_id(b"another chunk");
    let random_id_of_raw = seal(&random_id, &inner::inner(0, &random));
    let mut zero_nonce = good.clone();
    zero_nonce[..24].fill(0);
    let secret_frame = seal(&random_id, &compressed);
    let secret_bad_frame = seal(&random_id, &checksum);
    let zeros = vec![0u8; MIB];
    let zeros_inner = encode_chunk(&zeros, ORDINARY);
    assert_eq!(zeros_inner[0], 1, "zeros are compressed");
    let zeros_id = object.keyed_id(&zeros);
    // Frames of an RLE block of 16 bytes and a raw block: 45 bytes for 48 keeps the store-raw
    // rule exactly (16 × 45 = 15 × 48); 46 for 49 does not.
    let rle_raw = |raw: usize| {
        let frame = zstd_frame::frame(
            &Header::declaring((16 + raw) as u64),
            &[Block::Rle(b'a', 16), Block::Raw(vec![b'b'; raw])],
        );
        let plain = [vec![b'a'; 16], vec![b'b'; raw]].concat();
        (inner::inner(1, &frame), plain, frame.len())
    };
    let (edge_inner, edge_plain, edge_len) = rle_raw(32);
    assert_eq!((edge_len, edge_plain.len()), (45, 48));
    let edge_id = object.keyed_id(&edge_plain);
    let (past_inner, past_plain, past_len) = rle_raw(33);
    assert_eq!((past_len, past_plain.len()), (46, 49));
    let past_id = object.keyed_id(&past_plain);
    let raw_framed = inner::inner(1, &zstd_frame::raw_frame(&random));
    let random_keyed = object.keyed_id(&random);

    let ok = Some(chunk.as_slice());
    let data_open = "DataBlobOpen";
    #[rustfmt::skip]
    let tests = vec![
        keyed(&compressed).case("a compressed chunk of a two-chunk object", &[data_open, "KeyedBlobId"], "Ok", ok),
        keyed(&raw).case("a raw chunk of a two-chunk object", &[data_open, "KeyedBlobId"], "Ok", ok),
        open(ORDINARY, 1, random_id, 300, random_id_of_raw.clone()).case("the one chunk of a single-chunk object, random ID", &[data_open, "RandomBlobId"], "Ok", Some(&random)),
        open(SECRET, 3, random_id, 2_000, seal(&random_id, &raw)).case("a chunk of a secret object, random ID", &[data_open, "RandomBlobId"], "Ok", ok),
        with_aad(data_aad(&other_16, 0x01, &o.object_id, &o.dek_id, &id)).case("sealed under another vault's AAD", &["AadBinding"], "Decrypt", None),
        with_aad(data_aad(&o.vault_id, 0x01, &other_16, &o.dek_id, &id)).case("sealed under another object's AAD", &["AadBinding"], "Decrypt", None),
        with_aad(data_aad(&o.vault_id, 0x01, &o.object_id, &other_16, &id)).case("sealed under another DEK ID's AAD", &["AadBinding"], "Decrypt", None),
        with_aad(data_aad(&o.vault_id, 0x01, &o.object_id, &o.dek_id, &other_id)).case("sealed under another blob ID's AAD", &["AadBinding"], "Decrypt", None),
        with_aad(data_aad(&o.vault_id, 0x02, &o.object_id, &o.dek_id, &id)).case("sealed with kind byte 0x02", &["AadBinding"], "Decrypt", None),
        with_aad(cx::aad(labels::full("aad", "blob-meta"), &[&o.vault_id, &[0x01], &o.object_id, &o.dek_id, &id])).case("sealed under the blob-meta label", &["AadBinding"], "Decrypt", None),
        open(ORDINARY, 2, id, chunk.len(), cx::seal(&other, &object.aad(&id), &compressed, &nonce)).case("sealed under another key", &["AadBinding"], "Decrypt", None),
        open(ORDINARY, 2, other_id, chunk.len(), seal(&other_id, &compressed)).case("the blob ID of another chunk", &["BlobIdBinding"], "Binding", None),
        open(ORDINARY, 2, random_id, 300, random_id_of_raw).case("a random blob ID in a two-chunk object", &["BlobIdBinding"], "Binding", None),
        keyed(&with(&raw, 1, 1)).case("rsv 1", &["BlobInner"], "Padding", None),
        keyed(&with(&raw, 0, 2)).case("comp 2", &["BlobInner"], "Padding", None),
        keyed(&bad_pad).case("a pad byte not zero", &["BlobInner"], "Padding", None),
        keyed(&longer).case("one byte past the Padmé length", &["BlobInner"], "Padding", None),
        keyed(&header(0, 0, u32::try_from(MIB).expect("small") + 1)).case("payload_len 2^20 + 1", &["BlobInner"], "Limit", None),
        open(SECRET, 3, random_id, 2_000, secret_frame).case("a secret object's chunk with comp 1", &["SecretRaw"], "Padding", None),
        open(SECRET, 3, random_id, 2_000, secret_bad_frame).case("a secret object's chunk with comp 1 and a bad frame: comp is checked first", &["SecretRaw", "CheckOrder"], "Padding", None),
        keyed(&checksum).case("a frame with a content checksum", &["BlobFrame"], "Decompress", None),
        keyed(&over_declared).case("a frame holding more than it declares", &["BlobFrame"], "Decompress", None),
        open(ORDINARY, 2, id, chunk.len() + 1, good.clone()).case("plain_len one more than the frame declares", &["BlobFrame"], "Decompress", None),
        open(ORDINARY, 2, id, chunk.len() + 1, seal(&id, &raw)).case("a raw payload one byte shorter than plain_len", &["BlobFrame"], "Decompress", None),
        open(ORDINARY, 2, id, chunk.len() - 1, seal(&id, &raw)).case("a raw payload one byte longer than plain_len", &["BlobFrame"], "Decompress", None),
        open(ORDINARY, 2, edge_id, 48, seal(&edge_id, &edge_inner)).case("a frame of 45 bytes for 48: exactly 15/16, kept", &[data_open, "StoreRaw", "KeyedBlobId"], "Ok", Some(&edge_plain)),
        open(ORDINARY, 2, past_id, 49, seal(&past_id, &past_inner)).case("a frame of 46 bytes for 49 saves less than 1/16, so a writer stores the chunk raw", &["StoreRaw"], "Decompress", None),
        open(ORDINARY, 2, random_keyed, 300, seal(&random_keyed, &raw_framed)).case("random bytes in a raw-block frame longer than the chunk", &["StoreRaw"], "Decompress", None),
        open(ORDINARY, 2, other_id, 49, seal(&other_id, &past_inner)).case("a frame that saves less than 1/16 and a wrong blob ID: the store-raw rule is checked first", &["StoreRaw", "CheckOrder"], "Decompress", None),
        open(ORDINARY, 2, zeros_id, MIB, seal(&zeros_id, &zeros_inner)).case("plain_len exactly 2^20: a compressed 1 MiB of zeros", &[data_open, "PlainLenCap", "KeyedBlobId"], "Ok", Some(&zeros)),
        open(ORDINARY, 2, other_id, chunk.len(), seal(&other_id, &checksum)).case("a bad frame and a wrong blob ID: the frame is checked first", &["BlobFrame", "CheckOrder"], "Decompress", None),
        open(ORDINARY, 2, other_id, chunk.len() + 1, seal(&other_id, &raw)).case("a raw payload one byte shorter than plain_len and a wrong blob ID: the length is checked first", &["BlobFrame", "CheckOrder"], "Decompress", None),
        open(ORDINARY, 2, id, MIB + 1, seal(&id, &frame)).case("plain_len 2^20 + 1 is refused before decryption", &["PlainLenCap", "CheckOrder"], "Decompress", None),
        open(ORDINARY, 2, id, chunk.len(), good[..71].to_vec()).case("71 bytes, one short of a seal", &["SealShape"], "Truncated", None),
        open(ORDINARY, 2, id, chunk.len(), zero_nonce).case("an all-zero nonce", &["SealShape"], "ZeroValue", None),
    ];
    tests
}

// ----------------------------------------------------------------------------------------------
// Meta blobs (FS-57)

/// A meta blob's kind byte and the label of its key (FS-38, FS-57).
const META_KINDS: [(u8, &str); 5] = [
    (0x03, "index-key"),
    (0x04, "key-table-key"),
    (0x05, "location-key"),
    (0x06, "pack-table-key"),
    (0x08, "location-key"),
];

/// `K_kind_e = KDF(KEK_e, -, label, vault_id ‖ u32be(e))`.
fn meta_key(kek: &[u8; 32], vault_id: &[u8; 16], kind: u8, epoch: u32) -> [u8; 32] {
    let (_, purpose) = META_KINDS
        .iter()
        .find(|(code, _)| *code == kind)
        .expect("a meta kind");
    let context = [&vault_id[..], &epoch.to_be_bytes()].concat();
    cx::kdf(kek, None, labels::full("kdf", purpose), &context)
}

fn meta_aad(vault_id: &[u8; 16], kind: u8, epoch: u32, blob_id: &[u8; 32]) -> Vec<u8> {
    cx::aad(
        labels::full("aad", "blob-meta"),
        &[vault_id, &[kind], &epoch.to_be_bytes(), blob_id],
    )
}

fn meta_inputs(
    kek: &[u8; 32],
    vault_id: &[u8; 16],
    kind: u8,
    epoch: u32,
    blob_id: &[u8; 32],
) -> Vec<(&'static str, Input)> {
    vec![
        ("kek", Input::bytes(kek)),
        ("vaultId", Input::bytes(vault_id)),
        ("kind", Input::Int(i64::from(kind))),
        ("epoch", Input::Int(i64::from(epoch))),
        ("blobId", Input::bytes(blob_id)),
    ]
}

fn meta_tests(seed: &[u8; 32]) -> Vec<TestCase> {
    let mut stream = Stream::new(seed, "meta-blob");
    let kek: [u8; 32] = stream.bytes();
    let other_kek: [u8; 32] = stream.bytes();
    let vault_id: [u8; 16] = stream.bytes();
    let other_vault: [u8; 16] = stream.bytes();
    let epoch = 3;
    // A small CBOR map, `{1: h'00010203'}`, standing for a tree node.
    let cbor = [0xa1, 0x01, 0x44, 0x00, 0x01, 0x02, 0x03];
    let comments = [
        "a path-index node",
        "a key-table node",
        "a location node",
        "a pack-table node",
        "a GC-candidate node, under the location key",
    ];
    let mut tests: Vec<TestCase> = META_KINDS
        .iter()
        .zip(comments)
        .map(|((kind, _), comment)| {
            let blob_id: [u8; 32] = stream.bytes();
            let rand: [u8; 32] = stream.bytes();
            let key = meta_key(&kek, &vault_id, *kind, epoch);
            let aad = meta_aad(&vault_id, *kind, epoch, &blob_id);
            let nonce = cx::hedged_nonce(&key, &aad, &cbor, &rand);
            let mut inputs = meta_inputs(&kek, &vault_id, *kind, epoch, &blob_id);
            inputs.extend([("cbor", Input::bytes(&cbor)), ("rand", Input::bytes(&rand))]);
            TestCase::new(comment, &["MetaBlob"], "Ok", inputs).with_outputs(vec![
                ("nonce", Input::bytes(&nonce)),
                ("sealed", Input::Bytes(cx::seal(&key, &aad, &cbor, &nonce))),
            ])
        })
        .collect();

    let blob_id: [u8; 32] = stream.bytes();
    let other_id: [u8; 32] = stream.bytes();
    let nonce: [u8; 24] = stream.bytes();
    let location = 0x05;
    let key = meta_key(&kek, &vault_id, location, epoch);
    let sealed = cx::seal(
        &key,
        &meta_aad(&vault_id, location, epoch, &blob_id),
        &cbor,
        &nonce,
    );
    let open_bytes = |comment,
                      flag,
                      expect,
                      kek: &[u8; 32],
                      vault: &[u8; 16],
                      kind,
                      epoch,
                      blob_id: &[u8; 32],
                      sealed: &[u8]| {
        let mut inputs = meta_inputs(kek, vault, kind, epoch, blob_id);
        inputs.push(("sealed", Input::bytes(sealed)));
        let test = TestCase::new(comment, &[flag], expect, inputs);
        if expect == "Ok" {
            test.with_outputs(vec![("cbor", Input::bytes(&cbor))])
        } else {
            test
        }
    };
    let open = |comment, expect, kek: &[u8; 32], vault: &[u8; 16], kind, epoch, blob_id| {
        open_bytes(
            comment,
            "MetaBlobOpen",
            expect,
            kek,
            vault,
            kind,
            epoch,
            blob_id,
            &sealed,
        )
    };
    let mut zero_nonce = sealed.clone();
    zero_nonce[..24].fill(0);
    #[rustfmt::skip]
    let opens = [
        open("a location node opens", "Ok", &kek, &vault_id, location, epoch, &blob_id),
        open("opened as a GC-candidate node: same key, other kind byte", "Decrypt", &kek, &vault_id, 0x08, epoch, &blob_id),
        open("opened under another epoch", "Decrypt", &kek, &vault_id, location, epoch + 1, &blob_id),
        open("opened under another blob ID", "Decrypt", &kek, &vault_id, location, epoch, &other_id),
        open("opened in another vault", "Decrypt", &kek, &other_vault, location, epoch, &blob_id),
        open("opened with another epoch's KEK", "Decrypt", &other_kek, &vault_id, location, epoch, &blob_id),
        open_bytes("71 bytes, one short of a seal", "SealShape", "Truncated", &kek, &vault_id, location, epoch, &blob_id, &sealed[..71]),
        open_bytes("an all-zero nonce", "SealShape", "ZeroValue", &kek, &vault_id, location, epoch, &blob_id, &zero_nonce),
    ];
    tests.extend(opens);
    tests
}

/// Every flag of the set, with the rules and threats it cites (FS-94).
#[allow(clippy::too_many_lines, reason = "one table of notes")]
fn notes() -> Vec<(&'static str, &'static [&'static str], &'static str)> {
    vec![
        (
            "SmallFile",
            &["FS-52", "M-39"],
            "A file no longer than the 64 KiB minimum is one chunk; an empty file has none. `lengths` lists every chunk.",
        ),
        (
            "CutPoints",
            &["FS-52", "M-39", "T-84"],
            "FastCDC 2020 at level 2 with the vault's gear table: strict mask below 256 KiB, loose to 1 MiB, a cut before the matching byte, never at an odd last byte.",
        ),
        (
            "CutEdges",
            &["FS-52", "M-39", "T-84"],
            "Files found by search so a cut sits on an edge of the rule: at the minimum and one past it, at the switch from the strict to the loose mask (a loose-only match at 2⌊center/2⌋ cuts, one at 2⌊center/2⌋ − 1 does not), at the last position tested, an odd last byte that would match if it were tested, a repeated pattern that is cut only at the maximum, and a file between the average and the maximum where no position matches, so it is one chunk. The generator checks each with its one-byte chunker.",
        ),
        (
            "KeyedGear",
            &["FS-52", "M-39", "T-84"],
            "Another chunker_seed gives another gear table and other boundaries for the same data.",
        ),
        (
            "SecretFixed",
            &["FS-52", "T-84"],
            "A secret-class object is cut into 1 MiB chunks and a shorter last one, from its length alone, with no gear-table lookup; an empty one has none.",
        ),
        (
            "Padme",
            &["FS-54", "M-39", "T-84"],
            "padme(L) for L ≥ 2 rounds L up to a multiple of 2^(E−S); below 2 it is L.",
        ),
        (
            "InnerOk",
            &["FS-54", "M-39"],
            "A well-formed inner plaintext: comp 0 or 1, rsv 0, zero pad, length padme(6 + payload_len).",
        ),
        (
            "InnerPadding",
            &["FS-54", "T-39"],
            "Unknown comp, non-zero rsv or pad, or a length other than padme(6 + payload_len), is Padding.",
        ),
        (
            "InnerLimit",
            &["FS-54", "FS-11", "T-39"],
            "payload_len up to 2^20 is allowed; above it is Limit, checked before the length.",
        ),
        (
            "CheckOrder",
            &["FS-93", "FS-53", "FS-54", "T-39"],
            "Two faults at once: the first check in the order of the rules decides.",
        ),
        (
            "Compress",
            &["FS-53", "T-40"],
            "One single-segment zstd frame at level 3 with its content size, no checksum, no dictionary ID and window_log 20; equal output is only expected from the zstd version in the header.",
        ),
        (
            "StoreRaw",
            &["FS-53", "FS-56", "T-40"],
            "The frame is kept only if 16 × frame ≤ 15 × chunk; otherwise the chunk is stored with comp 0. A reader refuses a comp 1 payload that breaks the rule as Decompress, before its frame is checked, so each chunk has one encoding.",
        ),
        (
            "SecretRaw",
            &["FS-53", "FS-55", "T-40"],
            "Chunks of secret-class objects are never compressed; a secret chunk with comp 1 is Padding.",
        ),
        (
            "FrameOk",
            &["FS-53", "T-39"],
            "Frames FS-53 allows decode to exactly plain_len bytes, as libzstd 1.5.7 decodes them; a reader on another decoder must give the same results, and crypthix-core's own Decompressor requires 1.5.7. Raw, RLE and literals-only frames are built by hand.",
        ),
        (
            "FrameRejected",
            &["FS-53", "T-39"],
            "A frame that is not exactly one single-segment frame with content size plain_len in the shortest field that holds it, no checksum, no dictionary ID and the unused and reserved bits clear, that is cut off, or whose content differs from its declaration, is Decompress.",
        ),
        (
            "BlockSize",
            &["FS-53", "T-39"],
            "A block larger than min(window, 128 KiB), where a single segment's window is plain_len and an RLE block counts the bytes it regenerates, is Decompress, though libzstd 1.5.7 decodes such a frame in one pass.",
        ),
        (
            "PlainLenCap",
            &["FS-53", "FS-11", "T-39"],
            "plain_len may be 2^20; above that the chunk is Decompress before it is decrypted or decoded.",
        ),
        (
            "DataBlobSeal",
            &["FS-55", "FS-29", "M-8", "T-35"],
            "Seal(K_chunk, aad, inner, hedged nonce) with the AAD of FS-55; K_chunk and K_blobid from the DEK and dek_salt (FS-38).",
        ),
        (
            "KeyedBlobId",
            &["FS-55", "FS-56", "T-85"],
            "In an ordinary object of two or more chunks, blob_id = MAC(K_blobid, chunk), checked after opening.",
        ),
        (
            "RandomBlobId",
            &["FS-55", "T-85"],
            "In a single-chunk or secret-class object, blob_id is random and not recomputed.",
        ),
        (
            "DataBlobOpen",
            &["FS-55", "FS-56", "M-8"],
            "A data blob opens to its chunk.",
        ),
        (
            "AadBinding",
            &["FS-55", "M-8", "T-35"],
            "A blob sealed under an AAD naming another vault, object, DEK, blob ID, kind or label, or under another key, is Decrypt.",
        ),
        (
            "BlobIdBinding",
            &["FS-56", "T-85"],
            "A blob that opens but whose chunk does not MAC to its keyed blob ID is Binding.",
        ),
        (
            "BlobInner",
            &["FS-54", "T-39"],
            "A data blob whose inner plaintext is malformed is Padding, or Limit for payload_len over 2^20.",
        ),
        (
            "BlobFrame",
            &["FS-53", "T-39"],
            "A data blob whose payload is not exactly plain_len bytes when raw, or does not decode to exactly plain_len bytes when compressed, is Decompress.",
        ),
        (
            "SealShape",
            &["FS-28", "FS-03", "M-9"],
            "Input too short to be a seal is Truncated; an all-zero nonce is ZeroValue.",
        ),
        (
            "MetaBlob",
            &["FS-57", "FS-38", "M-8"],
            "Seal(K_kind_e, aad, CBOR, hedged nonce) with the AAD of FS-57; GC-candidate nodes use the location key.",
        ),
        (
            "MetaBlobOpen",
            &["FS-57", "M-8", "T-35"],
            "A meta blob opened with another kind byte, epoch, blob ID, vault or KEK is Decrypt.",
        ),
    ]
}

/// TV-07.
pub(crate) fn set() -> VectorSet {
    let seed = seed();
    let version = zstd_frame::version();
    assert_eq!(version, "1.5.7", "FS-53 pins zstd 1.5.7");
    VectorSet {
        file: "tv-07-chunk-blob.json",
        set: "TV-07",
        structure: "chunk-blob",
        seed: Some(seed),
        extra: vec![("zstd", version)],
        notes: notes(),
        groups: vec![
            ("Chunking", chunking_tests(&seed)),
            ("Padme", padme_tests()),
            ("InnerDecode", inner_tests(&seed)),
            ("Compress", compress_tests(&seed)),
            ("Decompress", decompress_tests()),
            ("DataBlobSeal", data_seal_tests(&seed)),
            ("DataBlobOpen", data_open_tests(&seed)),
            ("MetaBlob", meta_tests(&seed)),
        ],
    }
}
