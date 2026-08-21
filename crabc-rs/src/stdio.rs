//! Standard file-descriptor handles and descriptor replacement helpers.
//!
//! These APIs deliberately expose descriptor identity, not buffered Rust
//! streams. Replacing a standard descriptor can invalidate assumptions made by
//! higher-level I/O, so the `dup2_*` helpers only operate on the fixed Linux
//! descriptor numbers and do not maintain process-global state.

use core::mem::ManuallyDrop;

use crate::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use crate::{io, Result};

/// `STDIN_FILENO`—standard input, borrowed.
#[cfg(feature = "std")]
#[inline]
pub const fn stdin() -> BorrowedFd<'static> {
    // SAFETY: In `std` configurations Rust assumes the standard descriptors
    // remain valid for the process lifetime.
    unsafe { BorrowedFd::borrow_raw(0) }
}

/// `STDIN_FILENO`—standard input, borrowed in a no-std process.
#[cfg(not(feature = "std"))]
#[inline]
pub const unsafe fn stdin() -> BorrowedFd<'static> {
    // SAFETY: The caller must ensure descriptor 0 remains open and stable.
    unsafe { BorrowedFd::borrow_raw(0) }
}

/// `STDOUT_FILENO`—standard output, borrowed.
#[cfg(feature = "std")]
#[inline]
pub const fn stdout() -> BorrowedFd<'static> {
    // SAFETY: In `std` configurations Rust assumes the standard descriptors
    // remain valid for the process lifetime.
    unsafe { BorrowedFd::borrow_raw(1) }
}

/// `STDOUT_FILENO`—standard output, borrowed in a no-std process.
#[cfg(not(feature = "std"))]
#[inline]
pub const unsafe fn stdout() -> BorrowedFd<'static> {
    // SAFETY: The caller must ensure descriptor 1 remains open and stable.
    unsafe { BorrowedFd::borrow_raw(1) }
}

/// `STDERR_FILENO`—standard error, borrowed.
#[cfg(feature = "std")]
#[inline]
pub const fn stderr() -> BorrowedFd<'static> {
    // SAFETY: In `std` configurations Rust assumes the standard descriptors
    // remain valid for the process lifetime.
    unsafe { BorrowedFd::borrow_raw(2) }
}

/// `STDERR_FILENO`—standard error, borrowed in a no-std process.
#[cfg(not(feature = "std"))]
#[inline]
pub const unsafe fn stderr() -> BorrowedFd<'static> {
    // SAFETY: The caller must ensure descriptor 2 remains open and stable.
    unsafe { BorrowedFd::borrow_raw(2) }
}

/// Takes ownership of `STDIN_FILENO`.
///
/// # Safety
///
/// The caller must ensure descriptor 0 is open and that no other owner will
/// close it while the returned `OwnedFd` exists.
#[inline]
pub unsafe fn take_stdin() -> OwnedFd {
    // SAFETY: Forwarded from this function's ownership contract.
    unsafe { OwnedFd::from_raw_fd(0) }
}

/// Takes ownership of `STDOUT_FILENO`.
///
/// # Safety
///
/// The caller must ensure descriptor 1 is open and uniquely transferred.
#[inline]
pub unsafe fn take_stdout() -> OwnedFd {
    // SAFETY: Forwarded from this function's ownership contract.
    unsafe { OwnedFd::from_raw_fd(1) }
}

/// Takes ownership of `STDERR_FILENO`.
///
/// # Safety
///
/// The caller must ensure descriptor 2 is open and uniquely transferred.
#[inline]
pub unsafe fn take_stderr() -> OwnedFd {
    // SAFETY: Forwarded from this function's ownership contract.
    unsafe { OwnedFd::from_raw_fd(2) }
}

/// Returns the raw standard-input descriptor number.
#[inline]
pub const fn raw_stdin() -> RawFd {
    0
}

/// Returns the raw standard-output descriptor number.
#[inline]
pub const fn raw_stdout() -> RawFd {
    1
}

/// Returns the raw standard-error descriptor number.
#[inline]
pub const fn raw_stderr() -> RawFd {
    2
}

/// Duplicates `fd` onto standard input without creating an owning alias.
#[inline]
pub fn dup2_stdin<Fd: AsFd>(fd: Fd) -> Result<()> {
    let fd = fd.as_fd();
    if fd.as_raw_fd() != raw_stdin() {
        // Keep the fixed descriptor open after the operation. `ManuallyDrop`
        // makes the temporary ownership token non-owning after `dup2` closes
        // and replaces descriptor 0 in the kernel.
        let mut target = ManuallyDrop::new(unsafe { take_stdin() });
        io::dup2(fd, &mut target)?;
    }
    Ok(())
}

/// Duplicates `fd` onto standard output without creating an owning alias.
#[inline]
pub fn dup2_stdout<Fd: AsFd>(fd: Fd) -> Result<()> {
    let fd = fd.as_fd();
    if fd.as_raw_fd() != raw_stdout() {
        let mut target = ManuallyDrop::new(unsafe { take_stdout() });
        io::dup2(fd, &mut target)?;
    }
    Ok(())
}

/// Duplicates `fd` onto standard error without creating an owning alias.
#[inline]
pub fn dup2_stderr<Fd: AsFd>(fd: Fd) -> Result<()> {
    let fd = fd.as_fd();
    if fd.as_raw_fd() != raw_stderr() {
        let mut target = ManuallyDrop::new(unsafe { take_stderr() });
        io::dup2(fd, &mut target)?;
    }
    Ok(())
}
