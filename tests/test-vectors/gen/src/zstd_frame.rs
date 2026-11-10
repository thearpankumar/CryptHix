//! zstd frames for TV-07: hand-built raw and RLE frames (RFC 8878), which the negative vectors
//! bend one field at a time, and frames made by the zstd encoder (`zstd-safe`, the version the
//! set's header names) for the encoder-equality and valid-frame cases.

use zstd_safe::{CCtx, CParameter};

/// The magic number of a zstd frame, little-endian (RFC 8878 section 3.1.1).
const MAGIC: [u8; 4] = 0xFD2F_B528_u32.to_le_bytes();

/// The magic number of a skippable frame (RFC 8878 section 3.1.2).
const SKIPPABLE_MAGIC: [u8; 4] = 0x184D_2A50_u32.to_le_bytes();

/// The largest block, 128 KiB (RFC 8878 section 3.1.1.2.4).
pub(crate) const MAX_BLOCK: usize = 128 * 1024;

/// The unused bit of the frame header descriptor (RFC 8878 section 3.1.1.1.1).
pub(crate) const UNUSED_BIT: u8 = 0x10;

/// The reserved bit of the frame header descriptor.
pub(crate) const RESERVED_BIT: u8 = 0x08;

/// One block of a hand-built frame.
#[derive(Clone, Debug)]
pub(crate) enum Block {
    /// A raw block: its bytes as they are.
    Raw(Vec<u8>),
    /// An RLE block: one byte repeated.
    Rle(u8, usize),
    /// A compressed block with the given content, as [`literals_only`] builds it.
    Compressed(Vec<u8>),
    /// A block of the reserved type 3, which no decoder may accept, with the given content.
    Reserved(Vec<u8>),
}

/// The frame header fields a vector may set (RFC 8878 section 3.1.1.1).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Header {
    /// Single segment: no window descriptor, the window is the content size.
    pub(crate) single_segment: bool,
    /// The window descriptor byte, when not single segment.
    pub(crate) window: u8,
    /// The declared content size, if any.
    pub(crate) content_size: Option<u64>,
    /// The content-checksum flag; four checksum bytes follow the last block.
    pub(crate) checksum: bool,
    /// A one-byte dictionary ID.
    pub(crate) dict_id: Option<u8>,
    /// Descriptor bits FS-53 forbids, set as given: [`UNUSED_BIT`], which libzstd ignores and
    /// never sets, and [`RESERVED_BIT`].
    pub(crate) stray_bits: u8,
    /// The content-size flag, if not the shortest field that holds the size.
    pub(crate) fcs_flag: Option<u8>,
}

impl Header {
    /// A single-segment header declaring `content_size`, as FS-53 frames are.
    pub(crate) const fn declaring(content_size: u64) -> Self {
        Self {
            single_segment: true,
            window: 0,
            content_size: Some(content_size),
            checksum: false,
            dict_id: None,
            stray_bits: 0,
            fcs_flag: None,
        }
    }

    /// The window descriptor of `2^log` bytes: exponent `log − 10`, mantissa 0.
    pub(crate) const fn window_of(log: u8) -> u8 {
        (log - 10) << 3
    }
}

/// A frame with `header` and `blocks`, the last one marked as such.
pub(crate) fn frame(header: &Header, blocks: &[Block]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    let (fcs_flag, fcs) = match header.content_size {
        None => (0, Vec::new()),
        Some(size) => {
            // The shortest field, as libzstd writes it, unless the header names another.
            let shortest = match size {
                0..256 if header.single_segment => 0,
                256..65_792 => 1,
                0..0xFFFF_FFFF => 2,
                _ => 3,
            };
            let flag = header.fcs_flag.unwrap_or(shortest);
            let field = match flag {
                0 => vec![u8::try_from(size).expect("below 256")],
                1 => {
                    let value = u16::try_from(size - 256).expect("256 to 65,791");
                    value.to_le_bytes().to_vec()
                }
                2 => u32::try_from(size)
                    .expect("below 2^32")
                    .to_le_bytes()
                    .to_vec(),
                _ => size.to_le_bytes().to_vec(),
            };
            (flag, field)
        }
    };
    let mut descriptor = fcs_flag << 6;
    if header.single_segment {
        descriptor |= 0x20;
    }
    descriptor |= header.stray_bits;
    if header.checksum {
        descriptor |= 0x04;
    }
    if header.dict_id.is_some() {
        descriptor |= 0x01;
    }
    out.push(descriptor);
    if !header.single_segment {
        out.push(header.window);
    }
    if let Some(id) = header.dict_id {
        out.push(id);
    }
    out.extend_from_slice(&fcs);
    for (index, block) in blocks.iter().enumerate() {
        let last = u32::from(index + 1 == blocks.len());
        let (kind, size, body) = match block {
            Block::Raw(bytes) => (0, bytes.len(), bytes.clone()),
            Block::Rle(byte, len) => (1, *len, vec![*byte]),
            Block::Compressed(content) => (2, content.len(), content.clone()),
            Block::Reserved(content) => (3, content.len(), content.clone()),
        };
        let size = u32::try_from(size).expect("a block under 2^21 bytes");
        let block_header = last | (kind << 1) | (size << 3);
        out.extend_from_slice(&block_header.to_le_bytes()[..3]);
        out.extend_from_slice(&body);
    }
    if header.checksum {
        // Not the real XXH64 checksum: a reader must refuse the flag before it gets that far.
        out.extend_from_slice(&[0; 4]);
    }
    out
}

/// The content of a compressed block that holds `literals` as raw literals and no sequences
/// (RFC 8878 section 3.1.1.3): a three-byte literals section header (`Raw_Literals_Block`,
/// `Size_Format` 3, a 20-bit `Regenerated_Size`), the literals, and a `Number_of_Sequences`
/// byte of 0. It decodes to `literals` and is 4 bytes longer.
pub(crate) fn literals_only(literals: &[u8]) -> Vec<u8> {
    let size = u32::try_from(literals.len()).expect("under 2^20 bytes");
    assert!(size < 1 << 20, "a 20-bit Regenerated_Size");
    let mut content = vec![
        0b1100 | u8::try_from((size & 0xF) << 4).expect("four bits"),
        u8::try_from((size >> 4) & 0xFF).expect("a byte"),
        u8::try_from(size >> 12).expect("a byte"),
    ];
    content.extend_from_slice(literals);
    content.push(0);
    content
}

/// A single-segment frame of raw blocks holding `content`; an empty content gets one empty
/// block.
pub(crate) fn raw_frame(content: &[u8]) -> Vec<u8> {
    let mut blocks: Vec<Block> = content
        .chunks(MAX_BLOCK)
        .map(|piece| Block::Raw(piece.to_vec()))
        .collect();
    if blocks.is_empty() {
        blocks.push(Block::Raw(Vec::new()));
    }
    frame(&Header::declaring(content.len() as u64), &blocks)
}

/// A single-segment frame of RLE blocks holding `len` copies of `byte`.
pub(crate) fn rle_frame(byte: u8, len: usize) -> Vec<u8> {
    let mut blocks = Vec::new();
    let mut left = len;
    while left > 0 {
        let size = left.min(MAX_BLOCK);
        blocks.push(Block::Rle(byte, size));
        left -= size;
    }
    frame(&Header::declaring(len as u64), &blocks)
}

/// A skippable frame carrying `data`.
pub(crate) fn skippable(data: &[u8]) -> Vec<u8> {
    let mut out = SKIPPABLE_MAGIC.to_vec();
    let len = u32::try_from(data.len()).expect("short");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// The zstd encoder's frame of `data` with the parameters of FS-53 (level 3, content size, no
/// checksum, no dictionary ID, window log 20), or with the checksum on and the content size
/// off when `bent` asks, to make real frames FS-53 forbids.
pub(crate) fn encode(data: &[u8], bent: Bent) -> Vec<u8> {
    let mut cctx = CCtx::create();
    let parameters = [
        CParameter::CompressionLevel(3),
        CParameter::ContentSizeFlag(bent != Bent::NoContentSize),
        CParameter::ChecksumFlag(bent == Bent::Checksum),
        CParameter::DictIdFlag(false),
        CParameter::WindowLog(20),
    ];
    for parameter in parameters {
        cctx.set_parameter(parameter).expect("a valid parameter");
    }
    let mut out = vec![0u8; zstd_safe::compress_bound(data.len())];
    let written = cctx.compress2(&mut out[..], data).expect("compresses");
    out.truncate(written);
    out
}

/// Which FS-53 parameter [`encode`] breaks, if any.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Bent {
    /// The parameters of FS-53.
    No,
    /// With the content checksum.
    Checksum,
    /// Without the declared content size.
    NoContentSize,
}

/// The zstd version the generator links, which the set's header records.
pub(crate) fn version() -> &'static str {
    zstd_safe::version_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(frame: &[u8], capacity: usize) -> Result<Vec<u8>, usize> {
        let mut out = vec![0u8; capacity];
        let written = zstd_safe::decompress(&mut out[..], frame)?;
        out.truncate(written);
        Ok(out)
    }

    #[test]
    fn hand_built_frames_decode_with_zstd() {
        assert_eq!(decode(&raw_frame(b"hello"), 5), Ok(b"hello".to_vec()));
        assert_eq!(decode(&raw_frame(b""), 0), Ok(Vec::new()));
        assert_eq!(decode(&rle_frame(7, 300), 300), Ok(vec![7; 300]));
        let big = rle_frame(0, 1 << 20);
        assert_eq!(decode(&big, 1 << 20), Ok(vec![0; 1 << 20]));
        let windowed = Header {
            single_segment: false,
            window: Header::window_of(20),
            ..Header::declaring(5)
        };
        let windowed = frame(&windowed, &[Block::Raw(b"hello".to_vec())]);
        assert_eq!(decode(&windowed, 5), Ok(b"hello".to_vec()));
        // libzstd 1.5.7 decodes what FS-53 refuses: the unused bit, a wider content size.
        let hello = [Block::Raw(b"hello".to_vec())];
        for header in [
            Header {
                stray_bits: UNUSED_BIT,
                ..Header::declaring(5)
            },
            Header {
                fcs_flag: Some(2),
                ..Header::declaring(5)
            },
            Header {
                fcs_flag: Some(3),
                ..Header::declaring(5)
            },
        ] {
            assert_eq!(decode(&frame(&header, &hello), 5), Ok(b"hello".to_vec()));
        }
    }

    #[test]
    fn blocks_of_exactly_128_kib_decode() {
        let raw = raw_frame(&vec![7; MAX_BLOCK]);
        assert_eq!(raw.len(), 4 + 1 + 4 + 3 + MAX_BLOCK, "one raw block");
        assert_eq!(decode(&raw, MAX_BLOCK), Ok(vec![7; MAX_BLOCK]));
        let literals = vec![7; MAX_BLOCK - 4];
        let content = literals_only(&literals);
        assert_eq!(content.len(), MAX_BLOCK);
        let header = Header {
            single_segment: false,
            window: Header::window_of(17),
            ..Header::declaring(literals.len() as u64)
        };
        let compressed = frame(&header, &[Block::Compressed(content)]);
        assert_eq!(decode(&compressed, literals.len()), Ok(literals.clone()));
        // The block may be no larger than the window: here 2^17 bytes. With a single segment the
        // window is the content size, 4 bytes smaller than the block, and zstd refuses it.
        let single = frame(
            &Header::declaring(literals.len() as u64),
            &[Block::Compressed(literals_only(&literals))],
        );
        assert!(decode(&single, literals.len()).is_err());
    }

    #[test]
    fn a_reserved_block_fails() {
        let reserved = frame(&Header::declaring(5), &[Block::Reserved(b"hello".to_vec())]);
        assert!(decode(&reserved, 5).is_err());
    }

    #[test]
    fn content_sizes_take_the_shortest_field() {
        // Magic, descriptor, field, a three-byte block header.
        assert_eq!(raw_frame(&[0; 255]).len(), 4 + 1 + 1 + 3 + 255);
        assert_eq!(raw_frame(&[0; 256]).len(), 4 + 1 + 2 + 3 + 256);
        assert_eq!(rle_frame(0, 65_791).len(), 4 + 1 + 2 + 3 + 1);
        assert_eq!(rle_frame(0, 65_792).len(), 4 + 1 + 4 + 3 + 1);
    }

    #[test]
    fn encoder_frames_round_trip() {
        let data = b"abcabcabc".repeat(100);
        for bent in [Bent::No, Bent::Checksum, Bent::NoContentSize] {
            assert_eq!(decode(&encode(&data, bent), data.len()), Ok(data.clone()));
        }
    }

    #[test]
    fn the_pinned_version() {
        assert_eq!(version(), "1.5.7");
    }
}
