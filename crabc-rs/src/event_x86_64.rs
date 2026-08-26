//! The deliberately narrow Linux/x86-64 event facade.
//!
//! This target admits the scalar `eventfd2` counter seam and a closed typed
//! `poll(2)` readiness seam. `ppoll`, `pselect`, epoll, signalfd, and their
//! signal-mask or event-record contracts remain absent until each has
//! independent x86-64 evidence.

use core::convert::TryFrom;

use bitflags::bitflags;

pub use crate::time::Timespec;
use crate::{AsFd, BorrowedFd, Result};

pub use crate::eventfd::{EventfdFlags, eventfd, eventfd_read, eventfd_write};

bitflags! {
    /// Linux `POLL*` readiness flags used by [`poll`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct PollFlags: u16 {
        /// `POLLIN`.
        const IN = 0x0001;
        /// `POLLPRI`.
        const PRI = 0x0002;
        /// `POLLOUT`.
        const OUT = 0x0004;
        /// `POLLERR`.
        const ERR = 0x0008;
        /// `POLLHUP`.
        const HUP = 0x0010;
        /// `POLLNVAL`.
        const NVAL = 0x0020;
        /// `POLLRDNORM`.
        const RDNORM = 0x0040;
        /// `POLLRDBAND`.
        const RDBAND = 0x0080;
        /// `POLLWRNORM`.
        const WRNORM = 0x0100;
        /// `POLLWRBAND`.
        const WRBAND = 0x0200;
        /// Linux `POLLRDHUP`.
        const RDHUP = 0x2000;
        /// Preserve future Linux-defined bits reported by the kernel.
        const _ = !0;
    }
}

/// A borrowed Linux/x86-64 `struct pollfd` record.
///
/// The descriptor borrow keeps its owner alive for the complete call to
/// [`poll`]. Linux writes readiness bits into the record's private `revents`
/// field; the requested event mask is not changed by the syscall.
#[doc(alias = "pollfd")]
#[repr(C)]
#[derive(Clone, Debug)]
pub struct PollFd<'fd> {
    fd: BorrowedFd<'fd>,
    events: u16,
    revents: u16,
}

const _: () = assert!(core::mem::size_of::<PollFd<'static>>() == 8);
const _: () = assert!(core::mem::align_of::<PollFd<'static>>() == 4);
const _: () = assert!(core::mem::offset_of!(PollFd<'static>, fd) == 0);
const _: () = assert!(core::mem::offset_of!(PollFd<'static>, events) == 4);
const _: () = assert!(core::mem::offset_of!(PollFd<'static>, revents) == 6);

impl<'fd> PollFd<'fd> {
    /// Constructs a readiness record for `fd`.
    #[inline]
    pub fn new<Fd: AsFd>(fd: &'fd Fd, events: PollFlags) -> Self {
        Self::from_borrowed_fd(fd.as_fd(), events)
    }

    /// Constructs a readiness record from an existing descriptor borrow.
    #[inline]
    pub fn from_borrowed_fd(fd: BorrowedFd<'fd>, events: PollFlags) -> Self {
        Self {
            fd,
            events: events.bits(),
            revents: 0,
        }
    }

    /// Replaces the descriptor while retaining the requested event flags.
    #[inline]
    pub fn set_fd<Fd: AsFd>(&mut self, fd: &'fd Fd) {
        self.fd = fd.as_fd();
    }

    /// Clears readiness bits before reusing this record.
    #[inline]
    pub fn clear_revents(&mut self) {
        self.revents = 0;
    }

    /// Returns readiness reported by the most recent [`poll`] call.
    #[inline]
    pub fn revents(&self) -> PollFlags {
        PollFlags::from_bits_retain(self.revents as u16)
    }
}

impl AsFd for PollFd<'_> {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Waits for requested readiness on borrowed descriptors.
///
/// `None` waits indefinitely. A supplied [`Timespec`] is converted to the
/// millisecond representation required by Linux `poll(2)`, rounding up
/// non-zero sub-millisecond values. Inputs that cannot fit the signed Linux
/// millisecond range return [`crate::Errno::INVAL`] rather than being silently
/// truncated.
#[inline]
pub fn poll(fds: &mut [PollFd<'_>], timeout: Option<&Timespec>) -> Result<usize> {
    let timeout_ms = timeout.map(timeout_millis).transpose()?.unwrap_or(-1);
    // SAFETY: `PollFd` has the exact x86-64 `pollfd` layout, and each record's
    // descriptor borrow remains valid while the mutable slice is borrowed.
    unsafe { crabc_core::event::poll_raw(fds.as_mut_ptr().cast(), fds.len(), timeout_ms) }
}

fn timeout_millis(timeout: &Timespec) -> Result<i32> {
    if timeout.tv_sec < 0 || !(0..1_000_000_000).contains(&timeout.tv_nsec) {
        return Err(crate::Errno::INVAL);
    }
    let millis = timeout
        .tv_sec
        .checked_mul(1_000)
        .and_then(|seconds| seconds.checked_add((timeout.tv_nsec + 999_999) / 1_000_000))
        .and_then(|millis| i32::try_from(millis).ok())
        .ok_or(crate::Errno::INVAL)?;
    Ok(millis)
}
