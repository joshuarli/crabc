//! Standard file-descriptor handles and descriptor replacement helpers.
//!
//! These APIs deliberately expose descriptor identity, not buffered Rust
//! streams. Replacing a standard descriptor can invalidate assumptions made by
//! higher-level I/O, so the `dup2_*` helpers only operate on the fixed Linux
//! descriptor numbers and do not maintain process-global state.

use core::fmt;
use core::mem::ManuallyDrop;

use crate::fd::{AsFd, BorrowedFd, OwnedFd, RawFd};
use crate::{io, Result};

/// The result of formatting into a caller-owned byte slice.
///
/// `required` is the number of UTF-8 bytes the complete formatting operation
/// would have produced, while `written` is the number copied into the
/// destination. Neither field includes or reserves a trailing NUL: this is a
/// Rust byte-slice contract, not a C string contract. `required` saturates at
/// `usize::MAX` if a formatter reports more bytes than can be represented.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[must_use]
pub struct FormatResult {
    /// Number of bytes copied into the destination.
    pub written: usize,
    /// Number of bytes required for the complete formatted result.
    pub required: usize,
}

impl FormatResult {
    /// Returns whether the destination was too small for the complete result.
    #[must_use]
    pub const fn truncated(self) -> bool {
        self.written < self.required
    }
}

/// An allocation-free, UTF-8-aware formatter over caller-owned storage.
///
/// Formatting never fails merely because the destination is full: the writer
/// retains the complete required byte count and copies the largest valid UTF-8
/// prefix that fits. A custom [`fmt::Display`] implementation may still return
/// [`fmt::Error`] through the ordinary `fmt::Write` interface.
pub struct BoundedFormatter<'a> {
    output: &'a mut [u8],
    written: usize,
    required: usize,
    blocked: bool,
}

impl<'a> BoundedFormatter<'a> {
    /// Creates a formatter over `output` without allocating or clearing it.
    #[must_use]
    pub const fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            written: 0,
            required: 0,
            blocked: false,
        }
    }

    /// Finishes formatting and returns the bytes written and bytes required.
    #[must_use]
    pub const fn finish(self) -> FormatResult {
        FormatResult {
            written: self.written,
            required: self.required,
        }
    }
}

impl fmt::Write for BoundedFormatter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.required = self.required.saturating_add(value.len());

        let available = self.output.len().saturating_sub(self.written);
        if self.blocked || available == 0 {
            return Ok(());
        }

        // Never split a UTF-8 scalar when the destination ends in the middle
        // of one. This keeps the written prefix valid UTF-8 and lets a caller
        // resume from `required`/`written` information without repairing it.
        let mut copied = core::cmp::min(available, value.len());
        while copied > 0 && !value.is_char_boundary(copied) {
            copied -= 1;
        }
        if copied != 0 {
            let end = self.written + copied;
            self.output[self.written..end].copy_from_slice(&value.as_bytes()[..copied]);
            self.written = end;
        }
        if copied < value.len() {
            // A later formatter chunk must not backfill the unused tail when
            // this chunk stopped at a scalar boundary. The bytes written so
            // far remain a prefix of the complete formatted result.
            self.blocked = true;
        }
        Ok(())
    }
}

/// Formats typed [`fmt::Arguments`] into caller-owned storage.
///
/// This is the native replacement for the useful bounded-output shape of
/// `snprintf`, without C varargs, NUL termination, locale state, or `errno`.
/// The returned required count is independent of truncation, so callers can
/// choose a larger buffer or an owned Rust output type when needed.
pub fn format_to(
    output: &mut [u8],
    arguments: fmt::Arguments<'_>,
) -> core::result::Result<FormatResult, fmt::Error> {
    let mut formatter = BoundedFormatter::new(output);
    fmt::write(&mut formatter, arguments)?;
    Ok(formatter.finish())
}

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
