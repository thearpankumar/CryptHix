//! The `memfd_secret(2)` system call, which glibc does not wrap.
#![expect(
    unsafe_code,
    reason = "a raw system call and taking ownership of its descriptor"
)]

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

/// A new secret-memory file descriptor, close-on-exec.
///
/// # Errors
///
/// The kernel's error: `ENOSYS` (disabled, or a kernel before 5.14), `EPERM` (a seccomp
/// filter), `EINVAL` (which `memfd_secret(2)` defines as unknown flag bits) or a failure of this
/// one call, such as `EMFILE`, `ENFILE` and `ENOMEM`. The caller sorts them and falls back.
/// Where `libc` has no number for the call (see [`call`]) it is `ENOSYS` without asking the
/// kernel.
pub(crate) fn open() -> io::Result<OwnedFd> {
    let result = call()?;
    let fd = RawFd::try_from(result).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: the kernel just returned `fd` as a new open descriptor, so nothing else in the
    // process owns or will close it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

cfg_select! {
    // The targets for which `libc` defines `SYS_memfd_secret`. It lacks it for some, such as
    // LoongArch and RISC-V with musl, although their kernels have the call.
    any(
        all(
            target_env = "gnu",
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "csky",
                target_arch = "mips",
                target_arch = "mips32r6",
                target_arch = "mips64",
                target_arch = "mips64r6",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "riscv32",
                target_arch = "riscv64",
                target_arch = "s390x",
                target_arch = "sparc",
                target_arch = "sparc64",
                target_arch = "x86",
                target_arch = "x86_64",
            ),
        ),
        all(
            any(target_env = "musl", target_env = "ohos"),
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "s390x",
                target_arch = "wasm32",
                target_arch = "x86",
                target_arch = "x86_64",
            ),
        ),
        all(target_env = "uclibc", any(target_arch = "arm", target_arch = "mips")),
    ) => {
        /// `memfd_secret(O_CLOEXEC)`: the new descriptor, or the kernel's error.
        fn call() -> io::Result<libc::c_long> {
            // SAFETY: memfd_secret takes one integer of flags and touches no memory of this
            // process; it returns a new descriptor or -1 with errno set.
            let result = unsafe {
                libc::syscall(libc::SYS_memfd_secret, libc::c_long::from(libc::O_CLOEXEC))
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result)
            }
        }
    }
    _ => {
        /// `ENOSYS`: `libc` has no number for `memfd_secret` on this target, so the call is
        /// treated as missing and keys fall back to locked memory.
        fn call() -> io::Result<libc::c_long> {
            Err(io::Error::from_raw_os_error(libc::ENOSYS))
        }
    }
}
