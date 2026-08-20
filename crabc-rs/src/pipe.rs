//! Direct Linux pipe operations.
//!
//! The returned descriptors own their kernel resources and all operations use
//! the shared `crabc-core` syscall seam. No public C ABI or TLS `errno` state
//! is involved.

use bitflags::bitflags;

use crate::{OwnedFd, Result};

/// The maximum size of an atomically written pipe record on Linux.
pub const PIPE_BUF: usize = 4096;

bitflags! {
    /// Flags accepted by Linux `pipe2` on AArch64.
    ///
    /// Unknown bits are retained so callers which forward a newer
    /// kernel-defined flag do not lose it before the kernel validates it.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct PipeFlags: u32 {
        /// `O_NONBLOCK`.
        const NONBLOCK = 0x0000_0800;
        /// `O_DIRECT`, enabling packet-mode pipe semantics.
        const DIRECT = 0x0001_0000;
        /// `O_CLOEXEC`.
        const CLOEXEC = 0x0008_0000;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

/// Creates a pipe with neither end nonblocking nor close-on-exec.
#[inline]
pub fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    pipe_with(PipeFlags::empty())
}

/// Creates a pipe with the requested Linux `pipe2` flags.
#[inline]
pub fn pipe_with(flags: PipeFlags) -> Result<(OwnedFd, OwnedFd)> {
    let (reader, writer) = crabc_core::pipe::pipe2(flags.bits())?;
    // SAFETY: a successful Linux `pipe2` returns two new, non-negative,
    // uniquely-owned descriptors.
    unsafe { Ok((OwnedFd::from_raw_fd(reader), OwnedFd::from_raw_fd(writer))) }
}
