//! Which accounting of secret memory the running kernel uses, found by asking it (O1, T-31).
//!
//! Kernels before the CVE-2026-93243 fix check a `memfd_secret` mapping against the mapping
//! process's own `RLIMIT_MEMLOCK` when it is mapped. Kernels with the fix (upstream commit
//! 97d34aa65c29, Linux 7.3-rc2, and its stable backports such as 6.12.113) charge each secret
//! page to the user (`user->locked_vm`) when it is first faulted in, check the total against the
//! faulting process's limit, and refuse the fault past it.
//!
//! [`probe`] tells them apart with two processes of this user: a holder that faults in
//! [`HELD_PAGES`] secret pages and keeps them, then a tester that lowers its own limit to that
//! many pages and faults in one more. A per-process kernel gives the tester its page, which is
//! within its own limit; a per-user kernel counts the holder's pages too and refuses it. Pages
//! are faulted in by the raw `getrandom(2)` system call, as the crate does, so a refusal comes
//! back as `EFAULT` instead of a `SIGBUS`.
//!
//! The probe forks, so it runs only in a process that runs one test on one thread (`in_child`).

use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::ptr;

use rustix::io::Errno;
use rustix::mm::{self, MapFlags, ProtFlags};
use rustix::process::{self, Pid, Signal};

use super::{fork, run_child, set_memlock_limit, wait};

/// The secret pages the holder keeps, and the tester's limit in pages.
pub(crate) const HELD_PAGES: usize = 4;

/// How the running kernel accounts secret memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Accounting {
    /// Before the CVE-2026-93243 fix: each mapping against its own process's limit, when it is
    /// mapped.
    PerProcess,
    /// With the fix: every secret page of the user, when it is faulted in.
    PerUser,
    /// The kernel gives no secret memory at all.
    Unavailable,
}

impl Accounting {
    const ALL: [Self; 3] = [Self::PerProcess, Self::PerUser, Self::Unavailable];

    /// The name the probe prints and `cargo xtask kernel-test --expect` takes.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::PerProcess => "per-process",
            Self::PerUser => "per-user",
            Self::Unavailable => "unavailable",
        }
    }

    /// The model called `name`, if any.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|model| model.name() == name)
    }
}

/// What mapping secret pages and faulting them in came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// Every page is mapped and resident.
    Mapped,
    /// The lock limit: `EAGAIN` from `mmap`, or `EFAULT` from the fault-in.
    Refused,
    /// `memfd_secret` is missing or forbidden (`ENOSYS`, `EPERM`, `EINVAL`).
    Unavailable,
    /// Any other error, printed by the process that met it.
    Failed,
}

impl Outcome {
    const ALL: [Self; 4] = [Self::Mapped, Self::Refused, Self::Unavailable, Self::Failed];

    /// The byte a forked child sends its parent for this outcome.
    const fn code(self) -> u8 {
        match self {
            Self::Mapped => b'm',
            Self::Refused => b'r',
            Self::Unavailable => b'u',
            Self::Failed => b'f',
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|outcome| outcome.code() == code)
    }
}

/// Asks the kernel how it accounts secret memory (see the module docs).
pub(crate) fn probe() -> Accounting {
    let Some(holder) = Holder::hold(HELD_PAGES) else {
        return Accounting::Unavailable;
    };
    let page = rustix::param::page_size();
    let limit = u64::try_from(HELD_PAGES * page).expect("the limit fits in u64");
    let (tester, outcome) = fork_mapper(1, Some(limit), After::Exit);
    let status = wait(tester);
    assert_eq!(status.exit_status(), Some(0), "the tester: {status:?}");
    drop(holder);
    match outcome {
        Outcome::Mapped => Accounting::PerProcess,
        Outcome::Refused => Accounting::PerUser,
        Outcome::Unavailable | Outcome::Failed => {
            panic!("the holder got secret memory, but the tester's one page came to {outcome:?}")
        }
    }
}

/// A forked process of this user that keeps secret pages until it is dropped.
pub(crate) struct Holder(Pid);

impl Holder {
    /// Forks a holder of `pages` secret pages, all faulted in; `None` where the kernel gives no
    /// secret memory. Panics if it has secret memory but refuses the pages: the holder keeps
    /// this process's limit, which must have room for them.
    pub(crate) fn hold(pages: usize) -> Option<Self> {
        let (holder, outcome) = fork_mapper(pages, None, After::Hold);
        let holder = Self(holder);
        match outcome {
            Outcome::Mapped => Some(holder),
            Outcome::Unavailable => None,
            Outcome::Refused | Outcome::Failed => {
                panic!("a holder of {pages} secret pages within this process's limit: {outcome:?}")
            }
        }
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        // The holder may have exited already, after a failure; then only its status is left.
        match process::kill_process(self.0, Signal::KILL) {
            Ok(()) | Err(Errno::SRCH) => {}
            Err(error) => panic!("cannot end the holder: {error}"),
        }
        wait(self.0);
    }
}

/// What a forked mapper does once it has reported.
#[derive(Clone, Copy, PartialEq, Eq)]
enum After {
    Exit,
    /// Keeps its pages, if it mapped them, until it is killed.
    Hold,
}

/// Forks a child that lowers its `RLIMIT_MEMLOCK` to `limit` bytes if given, maps `pages`
/// secret pages and faults them in, and sends the outcome back through a pipe. Returns the
/// child and the outcome once it has reported. The child dies with the thread that forked it.
fn fork_mapper(pages: usize, limit: Option<u64>, after: After) -> (Pid, Outcome) {
    let (mut reader, mut writer) = io::pipe().expect("a pipe");
    let parent = process::getpid();
    let Some(child) = fork() else {
        run_child(move || {
            // A parent that crashes never drops its `Holder`, and a holder left running keeps
            // the output pipes the parent inherited open, so a test reading them would wait
            // forever: the kernel kills the mapper with its parent instead (PR_SET_PDEATHSIG,
            // prctl(2)), or the mapper ends itself if the parent died before that was set.
            process::set_parent_process_death_signal(Some(Signal::KILL))
                .expect("a parent-death signal");
            if process::getppid() != Some(parent) {
                return;
            }
            drop(reader);
            if let Some(bytes) = limit {
                set_memlock_limit(bytes);
            }
            let outcome = map_secret(pages);
            writer
                .write_all(&[outcome.code()])
                .expect("the parent reads the outcome");
            drop(writer);
            if after == After::Hold && outcome == Outcome::Mapped {
                loop {
                    std::thread::park();
                }
            }
        });
    };
    drop(writer);
    let mut code = [0];
    reader
        .read_exact(&mut code)
        .expect("the forked mapper reports before it exits");
    let outcome = Outcome::from_code(code[0]).expect("a known outcome");
    (child, outcome)
}

/// Maps `pages` pages of a new `memfd_secret` file and faults each in with the raw
/// `getrandom(2)` system call. The mapping is kept until the process ends.
#[expect(
    unsafe_code,
    reason = "a shared mapping and a system call that writes into it have no safe interface"
)]
fn map_secret(pages: usize) -> Outcome {
    let page = rustix::param::page_size();
    let len = pages * page;
    let fd = match memfd_secret() {
        Ok(fd) => fd,
        Err(error) => {
            return match error.raw_os_error() {
                Some(libc::ENOSYS | libc::EPERM | libc::EINVAL) => Outcome::Unavailable,
                _ => failed("memfd_secret", &error),
            };
        }
    };
    if let Err(error) = rustix::fs::ftruncate(&fd, u64::try_from(len).expect("fits in u64")) {
        return failed("ftruncate", &error);
    }
    // SAFETY: a new shared mapping at an address the kernel picks, of a file only this process
    // holds; it aliases no existing memory.
    let mapped = unsafe {
        mm::mmap(
            ptr::null_mut(),
            len,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::SHARED,
            &fd,
            0,
        )
    };
    let base = match mapped {
        Ok(base) => base.cast::<u8>(),
        Err(Errno::AGAIN) => return Outcome::Refused,
        Err(error) => return failed("mmap", &error),
    };
    for offset in (0..len).step_by(page) {
        // SAFETY: `offset` is below `len`, so the byte is inside the mapping.
        let byte = unsafe { base.add(offset) };
        loop {
            // SAFETY: the system call writes at most one byte, at `byte`, inside this mapping,
            // which nothing else refers to. The kernel writes it, so a page it will not back
            // fails the call with `EFAULT` instead of faulting this process.
            let filled = unsafe { libc::syscall(libc::SYS_getrandom, byte, 1_usize, 0_u32) };
            if filled == 1 {
                break;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EFAULT) => return Outcome::Refused,
                _ => return failed("getrandom", &error),
            }
        }
    }
    Outcome::Mapped
}

#[expect(clippy::print_stderr, reason = "the failure is only known here")]
fn failed(step: &str, error: &dyn std::fmt::Display) -> Outcome {
    eprintln!("secret memory probe: {step} failed: {error}");
    Outcome::Failed
}

/// `memfd_secret(O_CLOEXEC)`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[expect(unsafe_code, reason = "a raw system call and taking its descriptor")]
fn memfd_secret() -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;

    // SAFETY: memfd_secret takes one integer of flags and touches no memory of this process.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::c_long::from(libc::O_CLOEXEC)) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(fd).expect("a descriptor fits in an int");
    // SAFETY: the kernel just returned `fd` as a new open descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `ENOSYS`: the tests know the number of `memfd_secret` only for the targets CI runs them on.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn memfd_secret() -> io::Result<OwnedFd> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}
