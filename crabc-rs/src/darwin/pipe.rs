//! Darwin pipe creation over libSystem `pipe2`.

use core::ffi::c_int;

use super::errno::{self, Result};
use super::sys;
use crate::OwnedFd;

/// The maximum size of an atomically written pipe record on Darwin.
pub const PIPE_BUF: usize = sys::PIPE_BUF;

bitflags::bitflags! {
    /// Flags accepted by Darwin `pipe2`, with Darwin values.
    ///
    /// Darwin has no packet-mode pipes, so there is no `DIRECT` flag. Unknown
    /// bits are retained and passed to `pipe2`, which rejects them with
    /// [`crate::Errno::INVAL`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct PipeFlags: u32 {
        /// `O_NONBLOCK`.
        const NONBLOCK = sys::O_NONBLOCK.cast_unsigned();
        /// `O_CLOEXEC`.
        const CLOEXEC = sys::O_CLOEXEC.cast_unsigned();
        /// `O_CLOFORK`: close both ends in the child of a fork.
        const CLOFORK = sys::O_CLOFORK.cast_unsigned();
        /// Preserve unknown bits for libSystem validation.
        const _ = !0;
    }
}

/// Creates a pipe with the requested Darwin `pipe2` flags.
///
/// macOS 27 provides `pipe2`, so close-on-exec and close-on-fork are set
/// atomically with creation: no concurrent `fork` can observe either end
/// without them.
#[inline]
pub fn pipe_with(flags: PipeFlags) -> Result<(OwnedFd, OwnedFd)> {
    let mut fds: [c_int; 2] = [-1, -1];
    // SAFETY: `fds` is writable storage for the two descriptors `pipe2`
    // stores on success, and it stays live for the call.
    let result = unsafe { sys::pipe2(fds.as_mut_ptr(), flags.bits().cast_signed()) };
    errno::check(result)?;
    let [reader, writer] = fds;
    // SAFETY: a successful `pipe2` stored two new, non-negative descriptors;
    // ownership of the read end transfers to this owner.
    let reader = unsafe { OwnedFd::from_raw_fd(reader) };
    // SAFETY: as above, for the write end.
    let writer = unsafe { OwnedFd::from_raw_fd(writer) };
    Ok((reader, writer))
}
