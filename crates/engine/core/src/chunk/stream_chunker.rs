//! Cutting a reader.

use std::fmt;
use std::io::{ErrorKind, Read};

use crypthix_crypto::secure_mem::SecretBuf;

use crate::blob::ObjectClass;
use crate::chunk::cut::cut_for;
use crate::chunk::{ChunkParams, ChunkRef, GearTable, StreamError};

/// Cuts the bytes of a reader, for an object of a class, into the same chunks
/// [`Chunks`](crate::chunk::Chunks) gives for them in memory (FS-52), through a window of
/// protected memory twice the maximum chunk size.
///
/// The window is refilled whenever no more than one maximum chunk is left in it, so a cut
/// always sees either a full maximum chunk and at least one byte past it, or the end of the
/// input. That is also how each chunk knows whether it is the last. Short reads are fine and
/// [`ErrorKind::Interrupted`] is retried. After any error the chunker is fused: every later
/// call returns [`StreamError::Failed`].
///
/// ```
/// use crypthix_core::blob::ObjectClass;
/// use crypthix_core::chunk::{GearTable, StreamChunker};
/// use crypthix_crypto::key::KdfKey;
/// use crypthix_types::id::VaultId;
///
/// let gear = GearTable::derive(&KdfKey::random()?, &VaultId::try_from_bytes([1; 16])?)?;
/// let data = vec![0u8; (1 << 20) + 5];
/// let mut chunker = StreamChunker::new(&gear, ObjectClass::Ordinary, data.as_slice())?;
/// let first = chunker.next_chunk()?.expect("one full chunk");
/// assert_eq!((first.bytes().len(), first.is_last()), (1 << 20, false));
/// let second = chunker.next_chunk()?.expect("and the rest");
/// assert_eq!((second.bytes().len(), second.index(), second.is_last()), (5, 1, true));
/// assert!(chunker.next_chunk()?.is_none());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct StreamChunker<'g, R> {
    gear: &'g GearTable,
    class: ObjectClass,
    reader: R,
    params: ChunkParams,
    window: SecretBuf,
    /// Start of the bytes not yet cut.
    start: usize,
    /// End of the bytes read.
    end: usize,
    /// The reader has returned 0.
    eof: bool,
    /// Index of the next chunk.
    index: u64,
    /// A call failed; every later call fails too.
    failed: bool,
}

impl<'g, R: Read> StreamChunker<'g, R> {
    /// A chunker over `reader`, for an object of `class`; `gear` is used for the ordinary class
    /// only.
    ///
    /// # Errors
    ///
    /// [`StreamError::Memory`] if protected memory cannot be allocated for the 2 MiB window.
    pub fn new(gear: &'g GearTable, class: ObjectClass, reader: R) -> Result<Self, StreamError> {
        Self::with_params(gear, class, reader, ChunkParams::FORMAT_0)
    }

    /// A chunker at the scaled-down sizes of
    /// [`Chunks::scaled_for_fuzzing`](crate::chunk::Chunks::scaled_for_fuzzing), with a
    /// 2 KiB window. Not part of the API and not a format 0 cut; for the `chunker` fuzz target.
    ///
    /// # Errors
    ///
    /// [`StreamError::Memory`] if protected memory cannot be allocated for the window.
    #[doc(hidden)]
    pub fn scaled_for_fuzzing(
        gear: &'g GearTable,
        class: ObjectClass,
        reader: R,
    ) -> Result<Self, StreamError> {
        Self::with_params(gear, class, reader, ChunkParams::SCALED)
    }

    /// A chunker with other sizes and masks, for tests.
    pub(crate) fn with_params(
        gear: &'g GearTable,
        class: ObjectClass,
        reader: R,
        params: ChunkParams,
    ) -> Result<Self, StreamError> {
        let window = SecretBuf::try_zeroed(params.max * 2)?;
        Ok(Self {
            gear,
            class,
            reader,
            params,
            window,
            start: 0,
            end: 0,
            eof: false,
            index: 0,
            failed: false,
        })
    }

    /// The next chunk, or `None` after the last one. An empty input has no chunks.
    ///
    /// # Errors
    ///
    /// - [`StreamError::Io`] if the reader fails.
    /// - [`StreamError::Failed`] on every call after one that failed: the chunker is fused on
    ///   error, so an input it could not read to the end is never taken as complete.
    pub fn next_chunk(&mut self) -> Result<Option<ChunkRef<'_>>, StreamError> {
        if self.failed {
            return Err(StreamError::Failed);
        }
        if !self.eof
            && self.end.saturating_sub(self.start) <= self.params.max
            && let Err(error) = self.refill()
        {
            self.failed = true;
            return Err(error);
        }
        if self.start == self.end {
            return Ok(None);
        }
        let window = self.window.as_slice();
        // `start < end <= window.len()` always holds; failing instead keeps this panic-free.
        let Some(rest) = window.get(self.start..self.end) else {
            self.failed = true;
            return Err(StreamError::Failed);
        };
        let len = cut_for(self.class, self.gear, rest, &self.params);
        let Some(bytes) = rest.get(..len) else {
            self.failed = true;
            return Err(StreamError::Failed);
        };
        self.start += len;
        let index = self.index;
        self.index = self.index.saturating_add(1);
        let is_last = self.eof && self.start == self.end;
        Ok(Some(ChunkRef::new(bytes, index, is_last, self.class)))
    }

    /// Moves the bytes not yet cut to the front of the window and reads until it is full or the
    /// reader ends.
    fn refill(&mut self) -> Result<(), StreamError> {
        let window = self.window.as_mut_slice();
        if self.start > self.end || self.end > window.len() {
            return Err(StreamError::Failed);
        }
        window.copy_within(self.start..self.end, 0);
        self.end -= self.start;
        self.start = 0;
        loop {
            let free = match window.get_mut(self.end..) {
                Some(free) if !free.is_empty() => free,
                _ => break,
            };
            match self.reader.read(free) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                // A reader that claims more than it was given breaks the `Read` contract.
                Ok(read) if read > free.len() => {
                    return Err(std::io::Error::from(ErrorKind::InvalidData).into());
                }
                Ok(read) => self.end += read,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

/// Prints the position only, never the window.
impl<R> fmt::Debug for StreamChunker<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamChunker")
            .field("class", &self.class)
            .field("index", &self.index)
            .field("eof", &self.eof)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::ops::Range;

    use proptest::collection::vec;
    use proptest::prelude::{any, prop_assert_eq, proptest};

    use super::*;
    use crate::chunk::Chunks;
    use crate::test_data::gear_table as table;
    use crate::test_data::pseudo_random;

    /// A reader that returns at most the next step's bytes per call, and `Interrupted` where a
    /// step is 0.
    struct Choppy<'a> {
        data: &'a [u8],
        steps: Vec<usize>,
        call: usize,
    }

    impl Read for Choppy<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let step = self.steps[self.call % self.steps.len()];
            self.call += 1;
            if step == 0 {
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            let len = step.min(buf.len()).min(self.data.len());
            buf[..len].copy_from_slice(&self.data[..len]);
            self.data = &self.data[len..];
            Ok(len)
        }
    }

    /// Every chunk as its offsets, index, last flag and bytes.
    fn streamed<R: Read>(
        gear: &GearTable,
        class: ObjectClass,
        reader: R,
        params: ChunkParams,
        total: usize,
    ) -> Vec<(Range<usize>, u64, bool, Vec<u8>)> {
        let mut chunker = StreamChunker::with_params(gear, class, reader, params).expect("window");
        let mut out = Vec::new();
        let mut offset = 0;
        while let Some(chunk) = chunker.next_chunk().expect("reads") {
            let len = chunk.bytes().len();
            out.push((
                offset..offset + len,
                chunk.index(),
                chunk.is_last(),
                chunk.bytes().to_vec(),
            ));
            offset += len;
        }
        assert_eq!(offset, total);
        assert!(chunker.next_chunk().expect("reads").is_none(), "not fused");
        out
    }

    fn check_against_memory(
        gear: &GearTable,
        class: ObjectClass,
        data: &[u8],
        params: ChunkParams,
        steps: Vec<usize>,
    ) {
        let reader = Choppy {
            data,
            steps,
            call: 0,
        };
        let streamed = streamed(gear, class, reader, params, data.len());
        let in_memory: Vec<Range<usize>> = Chunks::with_params(gear, class, data, params).collect();
        assert_eq!(streamed.len(), in_memory.len());
        for (i, ((range, index, is_last, bytes), expected)) in
            streamed.iter().zip(&in_memory).enumerate()
        {
            assert_eq!(range, expected);
            assert_eq!(*index, i as u64);
            assert_eq!(*is_last, i + 1 == in_memory.len());
            assert_eq!(bytes.as_slice(), &data[expected.clone()]);
        }
    }

    // The tests that Miri runs use the scaled sizes: zeroing and wiping a 2 MiB window takes
    // minutes there.
    #[test]
    fn empty_input_has_no_chunks() {
        let gear = table(1);
        let mut chunker = StreamChunker::with_params(
            &gear,
            ObjectClass::Ordinary,
            io::empty(),
            ChunkParams::SCALED,
        )
        .expect("window");
        assert!(chunker.next_chunk().expect("reads").is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore = "a 2 MiB window takes minutes under Miri")]
    fn a_small_input_is_one_last_chunk() {
        let gear = table(1);
        let mut chunker =
            StreamChunker::new(&gear, ObjectClass::Ordinary, &b"tiny"[..]).expect("window");
        let chunk = chunker.next_chunk().expect("reads").expect("one chunk");
        assert_eq!(
            (chunk.bytes(), chunk.index(), chunk.is_last()),
            (&b"tiny"[..], 0, true)
        );
        assert_eq!(
            format!("{chunk:?}"),
            "ChunkRef { len: 4, index: 0, is_last: true }"
        );
    }

    #[test]
    fn reader_errors_are_returned() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("disk"))
            }
        }
        struct Liar;
        impl Read for Liar {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                Ok(buf.len() + 1)
            }
        }
        let gear = table(1);
        let mut chunker =
            StreamChunker::with_params(&gear, ObjectClass::Ordinary, Broken, ChunkParams::SCALED)
                .expect("window");
        assert!(matches!(chunker.next_chunk(), Err(StreamError::Io(_))));
        assert!(matches!(chunker.next_chunk(), Err(StreamError::Failed)));
        let mut chunker =
            StreamChunker::with_params(&gear, ObjectClass::Ordinary, Liar, ChunkParams::SCALED)
                .expect("window");
        assert!(
            matches!(chunker.next_chunk(), Err(StreamError::Io(error)) if error.kind() == ErrorKind::InvalidData)
        );
        assert!(matches!(chunker.next_chunk(), Err(StreamError::Failed)));
    }

    #[test]
    fn a_failed_read_is_never_taken_for_the_end() {
        /// Gives `data` once, then fails once, then reports the end.
        struct FailsOnce<'a> {
            data: &'a [u8],
            calls: usize,
        }
        impl Read for FailsOnce<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                match self.calls {
                    1 => {
                        let len = buf.len().min(self.data.len());
                        buf[..len].copy_from_slice(&self.data[..len]);
                        Ok(len)
                    }
                    2 => Err(io::Error::other("disk")),
                    _ => Ok(0),
                }
            }
        }
        let gear = table(1);
        let data = pseudo_random(4, 100);
        let reader = FailsOnce {
            data: &data,
            calls: 0,
        };
        let mut chunker =
            StreamChunker::with_params(&gear, ObjectClass::Ordinary, reader, ChunkParams::SCALED)
                .expect("window");
        assert!(matches!(chunker.next_chunk(), Err(StreamError::Io(_))));
        for _ in 0..2 {
            assert!(matches!(chunker.next_chunk(), Err(StreamError::Failed)));
        }
        assert!(format!("{chunker:?}").contains("failed: true"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "megabytes of input are slow under Miri")]
    fn full_size_streams_match_memory() {
        let gear = table(2);
        let data = pseudo_random(2, 5 << 20);
        for class in [ObjectClass::Ordinary, ObjectClass::Secret] {
            check_against_memory(&gear, class, &data, ChunkParams::FORMAT_0, vec![usize::MAX]);
            check_against_memory(
                &gear,
                class,
                &data,
                ChunkParams::FORMAT_0,
                vec![4096, 0, 65_537, 1],
            );
            let zeros = vec![0u8; 2 << 20];
            check_against_memory(
                &gear,
                class,
                &zeros,
                ChunkParams::FORMAT_0,
                vec![usize::MAX],
            );
        }
        // A secret object of exactly the maximum is one last chunk; one byte more is two.
        for (len, lengths) in [(1 << 20, vec![1 << 20]), ((1 << 20) + 1, vec![1 << 20, 1])] {
            let data = pseudo_random(3, len);
            let chunks = streamed(
                &gear,
                ObjectClass::Secret,
                data.as_slice(),
                ChunkParams::FORMAT_0,
                len,
            );
            let got: Vec<usize> = chunks.iter().map(|(range, ..)| range.len()).collect();
            assert_eq!(got, lengths);
        }
    }

    proptest! {
        #[test]
        #[cfg_attr(miri, ignore = "proptest is slow under Miri")]
        fn streaming_equals_in_memory(
            seed in 1u8..,
            data in vec(any::<u8>(), 0..6_000),
            steps in vec(0usize..700, 1..8),
            secret: bool,
        ) {
            // At least one step reads, so the reader always makes progress.
            let mut steps = steps;
            steps.push(1);
            let gear = table(seed);
            let class = if secret { ObjectClass::Secret } else { ObjectClass::Ordinary };
            check_against_memory(&gear, class, &data, ChunkParams::SCALED, steps);
        }

        #[test]
        #[cfg_attr(miri, ignore = "proptest is slow under Miri")]
        fn chunks_reassemble_the_stream(seed in 1u8.., data in vec(0u8..3, 0..6_000)) {
            let gear = table(seed);
            let chunks = streamed(
                &gear,
                ObjectClass::Ordinary,
                data.as_slice(),
                ChunkParams::SCALED,
                data.len(),
            );
            let rebuilt: Vec<u8> = chunks.iter().flat_map(|(_, _, _, bytes)| bytes.clone()).collect();
            prop_assert_eq!(rebuilt, data);
        }
    }
}
