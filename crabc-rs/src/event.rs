//! Direct Linux event-descriptor and polling operations.
//!
//! Poll descriptors borrow their underlying file descriptors, preventing a
//! safe caller from polling a resource after its owner has been dropped. The
//! implementation uses `ppoll` directly through `crabc-core`, never the C ABI
//! or TLS `errno`.

use bitflags::bitflags;

use crate::{AsFd, BorrowedFd, OwnedFd, Result};
use crate::time::Timespec;

bitflags! {
    /// Linux `POLL*` flags used by [`poll`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct PollFlags: u16 {
        /// `POLLIN`.
        const IN = 0x0001;
        /// `POLLPRI`.
        const PRI = 0x0002;
        /// `POLLOUT`.
        const OUT = 0x0004;
        /// `POLLRDNORM`.
        const RDNORM = 0x0040;
        /// `POLLWRNORM`.
        const WRNORM = 0x0100;
        /// `POLLRDBAND`.
        const RDBAND = 0x0080;
        /// `POLLWRBAND`.
        const WRBAND = 0x0200;
        /// `POLLERR`.
        const ERR = 0x0008;
        /// `POLLHUP`.
        const HUP = 0x0010;
        /// `POLLNVAL`.
        const NVAL = 0x0020;
        /// `POLLRDHUP`.
        const RDHUP = 0x2000;
        /// Preserve Linux extension bits.
        const _ = !0;
    }
}

/// A borrowed Linux `struct pollfd` record.
#[doc(alias = "pollfd")]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PollFd<'fd> {
    fd: BorrowedFd<'fd>,
    events: u16,
    revents: u16,
}

impl<'fd> PollFd<'fd> {
    /// Constructs a record which observes `fd` for `events`.
    #[inline]
    pub fn new<Fd: AsFd>(fd: &'fd Fd, events: PollFlags) -> Self {
        Self::from_borrowed_fd(fd.as_fd(), events)
    }

    /// Constructs a record from an existing descriptor borrow.
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

    /// Clears ready events before reusing this record.
    #[inline]
    pub fn clear_revents(&mut self) {
        self.revents = 0;
    }

    /// Returns the events observed by the most recent [`poll`] call.
    #[inline]
    pub fn revents(&self) -> PollFlags {
        PollFlags::from_bits_retain(self.revents)
    }
}

impl AsFd for PollFd<'_> {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

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

/// Waits for events on descriptor records.
///
/// `None` waits indefinitely. A supplied timeout is copied before crossing
/// the kernel boundary, so a kernel ABI implementation cannot mutate the
/// caller's immutable value.
#[inline]
pub fn poll(fds: &mut [PollFd<'_>], timeout: Option<&Timespec>) -> Result<usize> {
    let timeout = timeout.copied();
    let timeout = timeout
        .as_ref()
        .map_or(core::ptr::null(), |value| (value as *const Timespec).cast());
    // SAFETY: `PollFd` is exactly the Linux/AArch64 `pollfd` layout. Its
    // descriptor borrows keep every non-token descriptor open for the call;
    // the null signal-mask means the kernel receives no mask argument.
    unsafe {
        crabc_core::event::ppoll_raw(
            fds.as_mut_ptr().cast(),
            fds.len(),
            timeout,
            core::ptr::null(),
            0,
        )
    }
}
