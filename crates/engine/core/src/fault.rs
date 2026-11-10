//! Faults the unit tests inject where nothing else makes a dependency fail: protected memory
//! that cannot be allocated, and zstd calls that return an error.
//!
//! The module exists only under `cfg(test)`. Each call site that can fail this way checks it
//! in a `#[cfg(test)]` statement, so a build outside the unit tests has neither the check nor
//! this state. A fault is per thread, is consumed when it fires, and is cleared when the guard
//! [`inject`] returns is dropped, so it never reaches another test.
//!
//! Only the allocations `crypthix-core` makes itself are counted: the inner plaintext, the
//! compressor's scratch buffer, the decompressor's output, a raw chunk's opened copy, the
//! gear table and the stream window. Those inside `crypthix-crypto` (the CX-AEAD open buffer,
//! derived keys) have no seam here; that crate's own tests cover them.

use std::cell::Cell;

use crypthix_crypto::secure_mem::MemError;

/// A fault to inject.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Fault {
    /// After this many more allocations of protected memory succeed, the next fails with
    /// [`MemError::MapFailed`].
    Allocation(usize),
    /// The next `ZSTD_compress2` returns this error code, after it has written its output.
    Compress(usize),
    /// The next `ZSTD_DCtx_reset` returns this error code.
    Reset(usize),
}

thread_local! {
    static FAULT: Cell<Option<Fault>> = const { Cell::new(None) };
}

/// Clears the injected fault when dropped.
#[must_use = "the fault is cleared when the guard is dropped"]
pub(crate) struct Injected(());

impl Drop for Injected {
    fn drop(&mut self) {
        FAULT.with(|fault| fault.set(None));
    }
}

/// Injects `fault` on this thread until it fires or the guard is dropped.
pub(crate) fn inject(fault: Fault) -> Injected {
    FAULT.with(|slot| slot.set(Some(fault)));
    Injected(())
}

/// Whether the fault has fired.
pub(crate) fn fired() -> bool {
    FAULT.with(|fault| fault.get().is_none())
}

/// Called before each allocation of protected memory: fails it if an injected
/// [`Fault::Allocation`] has counted down to it.
pub(crate) fn allocation() -> Result<(), MemError> {
    FAULT.with(|fault| match fault.get() {
        Some(Fault::Allocation(0)) => {
            fault.set(None);
            Err(MemError::MapFailed)
        }
        Some(Fault::Allocation(left)) => {
            fault.set(Some(Fault::Allocation(left - 1)));
            Ok(())
        }
        _ => Ok(()),
    })
}

/// The result of `ZSTD_compress2`, or the injected [`Fault::Compress`] error in its place.
pub(crate) fn compress(result: Result<usize, usize>) -> Result<usize, usize> {
    FAULT.with(|fault| match fault.get() {
        Some(Fault::Compress(code)) => {
            fault.set(None);
            Err(code)
        }
        _ => result,
    })
}

/// The result of `ZSTD_DCtx_reset`, or the injected [`Fault::Reset`] error in its place.
pub(crate) fn reset(result: Result<usize, usize>) -> Result<usize, usize> {
    FAULT.with(|fault| match fault.get() {
        Some(Fault::Reset(code)) => {
            fault.set(None);
            Err(code)
        }
        _ => result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allocation_fault_counts_down_then_fires_once() {
        let guard = inject(Fault::Allocation(2));
        assert_eq!(allocation(), Ok(()));
        assert_eq!(allocation(), Ok(()));
        assert!(!fired());
        assert_eq!(allocation(), Err(MemError::MapFailed));
        assert!(fired());
        assert_eq!(allocation(), Ok(()), "a fault fires once");
        drop(guard);
    }

    #[test]
    fn zstd_faults_replace_only_their_own_call() {
        let _guard = inject(Fault::Compress(7));
        assert_eq!(reset(Ok(0)), Ok(0), "a compress fault leaves reset alone");
        assert_eq!(allocation(), Ok(()));
        assert_eq!(compress(Ok(5)), Err(7));
        assert_eq!(compress(Ok(5)), Ok(5));
        let _guard = inject(Fault::Reset(9));
        assert_eq!(compress(Ok(5)), Ok(5));
        assert_eq!(reset(Ok(0)), Err(9));
        assert_eq!(reset(Ok(0)), Ok(0));
    }

    #[test]
    fn dropping_the_guard_clears_the_fault() {
        drop(inject(Fault::Allocation(0)));
        assert_eq!(allocation(), Ok(()));
    }
}
