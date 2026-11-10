//! The fixed sizes and parameters of the data path (format spec 10.1 to 10.3).

/// The smallest chunk FastCDC cuts, 64 KiB (FS-52). Only an object's last chunk, or the one
/// chunk of an object smaller than this, may be shorter.
pub const MIN_CHUNK: usize = 64 * 1024;

/// The average chunk size FastCDC aims for, 256 KiB (FS-52).
pub const AVG_CHUNK: usize = 256 * 1024;

/// The largest chunk FastCDC cuts, 1 MiB (FS-52).
pub const MAX_CHUNK: usize = 1024 * 1024;

/// The largest `plain_len` of a chunk a reader accepts, 1 MiB (FS-11, FS-53); above it the
/// chunk is `Decompress` before anything is decrypted or allocated.
pub const MAX_PLAIN_LEN: u64 = 1 << 20;

/// The largest `payload_len` of an inner plaintext, 1 MiB (FS-54); above it the inner plaintext
/// is `Limit`.
pub const MAX_PAYLOAD_LEN: u64 = 1 << 20;

/// Bytes of the inner plaintext header: `comp ‖ rsv ‖ u32be payload_len` (FS-54).
pub const INNER_HEADER_LEN: usize = 6;

/// The zstd compression level (FS-53).
pub const ZSTD_LEVEL: i32 = 3;

/// The largest zstd window, as a base-2 logarithm: 1 MiB (FS-53).
pub const WINDOW_LOG: u32 = 20;

/// The libzstd version FS-53 pins, as `ZSTD_versionNumber` gives it: 1.5.7.
///
/// zstd output is not guaranteed to be the same across versions, so the encoder is only known
/// to match the test vectors under this one. It also defines which frames decode (FS-53), so
/// [`Decompressor`](crate::compress::Decompressor) refuses any other version too.
pub const ZSTD_VERSION: u32 = 10_507;

/// Bytes of the gear table: 256 little-endian `u64` words (FS-52).
pub const GEAR_TABLE_LEN: usize = 2048;

const _: () = {
    assert!(
        MAX_CHUNK as u64 == MAX_PLAIN_LEN,
        "a chunk and its plain_len share one cap"
    );
    assert!(
        MIN_CHUNK.is_multiple_of(2) && AVG_CHUNK.is_multiple_of(2) && MAX_CHUNK.is_multiple_of(2),
        "FastCDC cuts two bytes at a time"
    );
    assert!(MIN_CHUNK < AVG_CHUNK && AVG_CHUNK < MAX_CHUNK);
    assert!(1 << WINDOW_LOG == MAX_PLAIN_LEN);
};
