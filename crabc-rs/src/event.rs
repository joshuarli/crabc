//! Direct Linux event-descriptor and polling operations.
//!
//! Poll descriptors borrow their underlying file descriptors, preventing a
//! safe caller from polling a resource after its owner has been dropped. The
//! implementation uses `ppoll` directly through `crabc-core`, never the C ABI
//! or TLS `errno`.

use bitflags::bitflags;
use core::ffi::c_void;
use core::hash::{Hash, Hasher};

use crate::buffer::Buffer;
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

/// Direct Linux epoll operations.
pub mod epoll {
    use super::*;

    bitflags! {
        /// Flags accepted by Linux `epoll_create1`.
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct CreateFlags: u32 {
            /// `EPOLL_CLOEXEC`.
            const CLOEXEC = 0x0008_0000;
            /// Preserve future Linux-defined bits.
            const _ = !0;
        }
    }

    bitflags! {
        /// Readiness and behavior flags accepted by Linux epoll.
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
        pub struct EventFlags: u32 {
            /// `EPOLLIN`.
            const IN = 0x0000_0001;
            /// `EPOLLOUT`.
            const OUT = 0x0000_0004;
            /// `EPOLLPRI`.
            const PRI = 0x0000_0002;
            /// `EPOLLERR`.
            const ERR = 0x0000_0008;
            /// `EPOLLHUP`.
            const HUP = 0x0000_0010;
            /// `EPOLLRDNORM`.
            const RDNORM = 0x0000_0040;
            /// `EPOLLRDBAND`.
            const RDBAND = 0x0000_0080;
            /// `EPOLLWRNORM`.
            const WRNORM = 0x0000_0100;
            /// `EPOLLWRBAND`.
            const WRBAND = 0x0000_0200;
            /// `EPOLLMSG`.
            const MSG = 0x0000_0400;
            /// `EPOLLRDHUP`.
            const RDHUP = 0x0000_2000;
            /// `EPOLLET`.
            const ET = 0x8000_0000;
            /// `EPOLLONESHOT`.
            const ONESHOT = 0x4000_0000;
            /// `EPOLLWAKEUP`.
            const WAKEUP = 0x2000_0000;
            /// `EPOLLEXCLUSIVE`.
            const EXCLUSIVE = 0x1000_0000;
            /// Preserve future Linux-defined bits.
            const _ = !0;
        }
    }

    /// A record of an event returned by Linux `epoll_wait`.
    ///
    /// Linux/AArch64 uses the naturally aligned 16-byte `epoll_event` layout:
    /// a 32-bit event mask followed by four bytes of padding and an eight-byte
    /// data union. (The packed x86_64 ABI is intentionally outside this
    /// target's contract.)
    #[repr(C)]
    #[derive(Clone, Copy, Eq, PartialEq, Hash)]
    pub struct Event {
        /// Which readiness or behavior flags occurred.
        pub flags: EventFlags,
        /// Caller-provided data associated with the registered descriptor.
        pub data: EventData,
    }

    /// Data associated with an [`Event`], represented as a 64-bit token or
    /// pointer without crossing the C ABI.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union EventData {
        as_u64: u64,
        pointer: *mut c_void,
    }

    impl EventData {
        /// Creates event data containing a 64-bit integer token.
        #[inline]
        pub const fn new_u64(value: u64) -> Self {
            Self { as_u64: value }
        }

        /// Creates event data containing a pointer token.
        #[inline]
        pub const fn new_ptr(value: *mut c_void) -> Self {
            Self { pointer: value }
        }

        /// Reads the data as a 64-bit integer token.
        #[inline]
        pub fn u64(self) -> u64 {
            // SAFETY: The union is intentionally transparent at this API
            // boundary; both representations are exactly eight bytes.
            unsafe { self.as_u64 }
        }

        /// Reads the data as a pointer token.
        #[inline]
        pub fn ptr(self) -> *mut c_void {
            // SAFETY: See [`Self::u64`].
            unsafe { self.pointer }
        }
    }

    impl PartialEq for EventData {
        #[inline]
        fn eq(&self, other: &Self) -> bool {
            self.u64() == other.u64()
        }
    }

    impl Eq for EventData {}

    impl Hash for EventData {
        #[inline]
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.u64().hash(state);
        }
    }

    /// Creates an epoll descriptor.
    #[inline]
    #[doc(alias = "epoll_create1")]
    pub fn create(flags: CreateFlags) -> Result<OwnedFd> {
        let fd = crabc_core::event::epoll_create1(flags.bits())?;
        // SAFETY: a successful Linux `epoll_create1` returns one new,
        // non-negative, uniquely-owned descriptor.
        unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
    }

    /// Registers a source descriptor with an epoll object.
    #[inline]
    #[doc(alias = "epoll_ctl")]
    pub fn add<EpollFd: AsFd, SourceFd: AsFd>(
        epoll: EpollFd,
        source: SourceFd,
        data: EventData,
        event_flags: EventFlags,
    ) -> Result<()> {
        let epoll = epoll.as_fd();
        let source = source.as_fd();
        let event = Event { flags: event_flags, data };
        // SAFETY: `event` is a naturally aligned AArch64 epoll record alive
        // for the syscall; both descriptor borrows remain open for the call.
        unsafe {
            crabc_core::event::epoll_ctl_raw(
                epoll.as_raw_fd(),
                1,
                source.as_raw_fd(),
                (&event as *const Event).cast(),
            )
        }
    }

    /// Modifies a source descriptor's epoll registration.
    #[inline]
    #[doc(alias = "epoll_ctl")]
    pub fn modify<EpollFd: AsFd, SourceFd: AsFd>(
        epoll: EpollFd,
        source: SourceFd,
        data: EventData,
        event_flags: EventFlags,
    ) -> Result<()> {
        let epoll = epoll.as_fd();
        let source = source.as_fd();
        let event = Event { flags: event_flags, data };
        // SAFETY: See [`add`]; operation three selects Linux `EPOLL_CTL_MOD`.
        unsafe {
            crabc_core::event::epoll_ctl_raw(
                epoll.as_raw_fd(),
                3,
                source.as_raw_fd(),
                (&event as *const Event).cast(),
            )
        }
    }

    /// Removes a source descriptor from an epoll object.
    #[inline]
    #[doc(alias = "epoll_ctl")]
    pub fn delete<EpollFd: AsFd, SourceFd: AsFd>(epoll: EpollFd, source: SourceFd) -> Result<()> {
        let epoll = epoll.as_fd();
        let source = source.as_fd();
        // SAFETY: Linux requires a null event pointer for `EPOLL_CTL_DEL`.
        unsafe {
            crabc_core::event::epoll_ctl_raw(
                epoll.as_raw_fd(),
                2,
                source.as_raw_fd(),
                core::ptr::null(),
            )
        }
    }

    /// Waits for registered events, initializing the supplied event buffer.
    ///
    /// `timeout` is expressed as a `Timespec` and rounded up to the
    /// millisecond representation used by Linux `epoll_pwait`, matching the
    /// pinned Rustix backend. `None` waits indefinitely.
    #[inline]
    #[allow(private_interfaces)]
    pub fn wait<EpollFd: AsFd, Buf: Buffer<Event>>(
        epoll: EpollFd,
        mut event_list: Buf,
        timeout: Option<&Timespec>,
    ) -> Result<Buf::Output> {
        let timeout = timeout.map(timeout_millis).transpose()?.unwrap_or(-1);
        let epoll = epoll.as_fd();
        let (events, maxevents) = event_list.parts_mut();
        // SAFETY: `Buffer` supplies writable storage for exactly `maxevents`
        // records, and the epoll descriptor remains open through the borrow.
        let ready = unsafe {
            crabc_core::event::epoll_wait_raw(
                epoll.as_raw_fd(),
                events.cast(),
                maxevents,
                timeout,
            )?
        };
        // SAFETY: Linux initialized exactly the returned event prefix.
        unsafe { Ok(event_list.assume_init(ready)) }
    }

    fn timeout_millis(timeout: &Timespec) -> Result<i32> {
        if timeout.tv_sec < 0 || timeout.tv_nsec < 0 {
            return Err(crate::Errno::INVAL);
        }
        let millis = timeout
            .tv_sec
            .checked_mul(1_000)
            .and_then(|seconds| {
                seconds.checked_add((timeout.tv_nsec + 999_999) / 1_000_000)
            })
            .and_then(|millis| i32::try_from(millis).ok())
            .ok_or(crate::Errno::INVAL)?;
        Ok(millis)
    }
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
