//! A plaintext buffer in protected memory.

use std::fmt;
use std::ops::Deref;

use crate::secure_mem::secret_vec::SecretVec;
use crate::secure_mem::{Level, MemError};

/// Bytes of plaintext, wiped before they are freed (T-31).
///
/// On Linux they are in their own protected mapping: locked if `RLIMIT_MEMLOCK` allows, left
/// out of core dumps and forked children, between two guard pages. A buffer the kernel will not
/// map is refused, never put on the heap.
///
/// The first buffer of a process, even an empty one, sets up the key pool with
/// [`Config::default`](crate::secure_mem::Config::default) if
/// [`init`](crate::secure_mem::init) has not, as the first key does, so an `init` after it
/// fails with [`MemError::AlreadyInitialised`].
///
/// On Linux each buffer costs what its own mapping costs: three kernel memory areas (two guard
/// pages and its data), up to seven system calls over its life (`mmap`, two `mprotect`s, two
/// `madvise`s, `mlock` when it is locked, and `munmap`), and at least one whole page however few
/// bytes it holds. With the default `vm.max_map_count` of 65530 a process runs out of memory
/// areas at about 21 000 live buffers, so a hot path should reuse its buffers rather than make
/// one per small value.
///
/// Under Miri and on other systems it is plain heap memory ([`Level::Heap`]): wiped before it
/// is freed, but not locked, guarded, or kept out of core dumps and forked children.
///
/// The length is fixed when it is made, so the bytes are never copied by a reallocation. It
/// never prints its bytes. Reading it in any way (`Deref` and `AsRef` too) panics on Linux in a
/// child forked without `exec` after it was made ([`secure_mem`](crate::secure_mem#fork)).
///
/// ```
/// use crypthix_crypto::secure_mem::SecretBuf;
///
/// let buf = SecretBuf::try_copy_from(b"plaintext")?;
/// assert_eq!(buf.as_slice(), b"plaintext");
/// assert_eq!(format!("{buf:?}"), "SecretBuf(9 bytes)");
/// # Ok::<(), crypthix_crypto::secure_mem::MemError>(())
/// ```
pub struct SecretBuf(SecretVec<u8>);

impl SecretBuf {
    /// A buffer of `len` zero bytes.
    ///
    /// # Errors
    ///
    /// - [`MemError::TooLarge`] if `len`, rounded up to whole pages and with two guard pages,
    ///   passes `isize::MAX` bytes.
    /// - [`MemError::MapFailed`] if the kernel maps neither a locked nor a dump-excluded buffer
    ///   of `len` bytes (heap memory under Miri and off Linux).
    ///   [`Status::buffer_reason`](crate::secure_mem::Status::buffer_reason) says why.
    pub fn try_zeroed(len: usize) -> Result<Self, MemError> {
        SecretVec::try_new(len).map(Self)
    }

    /// A buffer holding a copy of `bytes`. The caller wipes the original if it is secret.
    ///
    /// # Errors
    ///
    /// As for [`try_zeroed`](SecretBuf::try_zeroed).
    pub fn try_copy_from(bytes: &[u8]) -> Result<Self, MemError> {
        let mut buf = Self::try_zeroed(bytes.len())?;
        buf.as_mut_slice().copy_from_slice(bytes);
        Ok(buf)
    }

    /// The bytes.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the buffer was made
    /// ([`secure_mem`](crate::secure_mem#fork)).
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// The bytes, to fill or change in place.
    ///
    /// # Panics
    ///
    /// On Linux, in a child forked without `exec` after the buffer was made
    /// ([`secure_mem`](crate::secure_mem#fork)).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    /// The protection the bytes got; `None` for an empty buffer, which maps nothing.
    #[must_use]
    pub fn level(&self) -> Option<Level> {
        self.0.level()
    }
}

impl Deref for SecretBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for SecretBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf({} bytes)", self.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroed_is_zero_and_writable() {
        let mut buf = SecretBuf::try_zeroed(5).expect("five bytes can be had");
        assert_eq!(buf.as_slice(), &[0; 5]);
        buf.as_mut_slice()[4] = 1;
        assert_eq!(&*buf, &[0, 0, 0, 0, 1]);
        assert!(buf.level().is_some(), "a non-empty buffer maps memory");
    }

    #[test]
    fn a_copy_holds_the_bytes() {
        let buf = SecretBuf::try_copy_from(b"abc").expect("three bytes can be had");
        assert_eq!(buf.as_slice(), b"abc");
    }

    #[test]
    fn an_impossible_length_is_an_error_not_an_abort() {
        assert_eq!(
            SecretBuf::try_zeroed(usize::MAX).err(),
            Some(MemError::TooLarge)
        );
        assert_eq!(
            SecretBuf::try_zeroed(isize::MAX.unsigned_abs()).err(),
            Some(MemError::TooLarge)
        );
    }

    #[test]
    fn empty_buffers_work() {
        let buf = SecretBuf::try_copy_from(&[]).expect("an empty buffer maps nothing");
        assert!(buf.is_empty());
        assert_eq!(buf.level(), None);
    }
}
