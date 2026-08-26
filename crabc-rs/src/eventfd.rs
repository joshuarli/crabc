//! Typed Linux `eventfd2` counter operations shared by admitted facades.
//!
//! An eventfd counter has no architecture-specific user-memory record: Linux
//! receives its initial value and flags as scalar syscall arguments, while
//! reads and writes use one private eight-byte counter value through
//! `crabc-core`. Keeping this narrow seam separate from polling and epoll
//! records lets a target admit the counter without inheriting those distinct
//! ABI contracts.

use bitflags::bitflags;

use crate::{AsFd, OwnedFd, Result};

bitflags! {
    /// Flags accepted by Linux `eventfd2`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct EventfdFlags: u32 {
        /// `EFD_SEMAPHORE`.
        const SEMAPHORE = 0x1;
        /// `EFD_NONBLOCK`.
        const NONBLOCK = 0x0000_0800;
        /// `EFD_CLOEXEC`.
        const CLOEXEC = 0x0008_0000;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

/// Creates an event counter descriptor.
#[inline]
pub fn eventfd(initval: u32, flags: EventfdFlags) -> Result<OwnedFd> {
    let fd = crabc_core::event::eventfd(initval, flags.bits())?;
    // SAFETY: a successful Linux `eventfd2` returns one new, non-negative,
    // uniquely-owned descriptor.
    unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
}

/// Reads one complete eventfd counter record from a borrowed descriptor.
///
/// Linux eventfd records are exactly eight little-endian bytes. The native
/// helper keeps that fixed record private and returns its typed `u64` value;
/// an ordinary byte buffer cannot accidentally request a partial record.
/// Without `EFD_SEMAPHORE`, a successful read returns the accumulated counter
/// and resets it to zero. With `EFD_SEMAPHORE`, Linux returns one and
/// decrements the counter by one.
#[inline]
pub fn eventfd_read<Fd: AsFd>(fd: Fd) -> Result<u64> {
    crabc_core::event::eventfd_read(fd.as_fd().as_raw_fd())
}

/// Adds one `u64` increment to a borrowed eventfd counter.
///
/// Linux requires exactly one eight-byte little-endian record for this
/// operation. `u64::MAX` is rejected by Linux, and a nonblocking descriptor
/// reports `EAGAIN` when the counter would overflow instead of waiting.
#[inline]
pub fn eventfd_write<Fd: AsFd>(fd: Fd, value: u64) -> Result<()> {
    crabc_core::event::eventfd_write(fd.as_fd().as_raw_fd(), value)
}
