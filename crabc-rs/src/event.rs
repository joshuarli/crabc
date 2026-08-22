//! Direct Linux event-descriptor and polling operations.
//!
//! Poll descriptors borrow their underlying file descriptors, preventing a
//! safe caller from polling a resource after its owner has been dropped. The
//! implementation uses `ppoll` directly through `crabc-core`, never the C ABI
//! or TLS `errno`.

use bitflags::bitflags;
use core::ffi::c_void;
use core::hash::{Hash, Hasher};
use core::mem::size_of;
use core::ptr;

use crate::buffer::Buffer;
use crate::signal::SignalSet;
use crate::{AsFd, BorrowedFd, OwnedFd, Result};
pub use crate::time::Timespec;

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

    /// Creates an epoll descriptor using the legacy `epoll_create(size)`
    /// contract.
    ///
    /// Linux/AArch64 has no separate legacy syscall. A value of zero is
    /// rejected as `EINVAL`, while any positive value is accepted and ignored
    /// by the historical interface; the direct implementation therefore uses
    /// `epoll_create1(0)` after validating that contract.
    #[inline]
    #[doc(alias = "epoll_create")]
    pub fn create_legacy(size: usize) -> Result<OwnedFd> {
        if size == 0 {
            return Err(crate::Errno::INVAL);
        }
        create(CreateFlags::empty())
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
        event_list: Buf,
        timeout: Option<&Timespec>,
    ) -> Result<Buf::Output> {
        wait_with_mask(epoll, event_list, timeout, None)
    }

    /// Waits for registered events while temporarily installing a signal mask.
    ///
    /// `timeout` is copied before entering Linux because `epoll_pwait` accepts
    /// a millisecond timeout and does not expose a mutable Rust value. A
    /// supplied mask is installed atomically for the wait and restored by the
    /// kernel before this function returns. `None` preserves the ordinary
    /// unmasked [`wait`] behavior.
    #[inline]
    #[allow(private_interfaces)]
    pub fn wait_with_mask<EpollFd: AsFd, Buf: Buffer<Event>>(
        epoll: EpollFd,
        mut event_list: Buf,
        timeout: Option<&Timespec>,
        mask: Option<&SignalSet>,
    ) -> Result<Buf::Output> {
        let timeout = timeout.map(timeout_millis).transpose()?.unwrap_or(-1);
        let epoll = epoll.as_fd();
        let (events, maxevents) = event_list.parts_mut();
        let sigmask = mask.map_or(core::ptr::null(), |mask| {
            (mask.kernel_bits() as *const u64).cast()
        });
        // SAFETY: `Buffer` supplies writable storage for exactly `maxevents`
        // records, the epoll descriptor remains open through the borrow, and
        // `SignalSet` supplies one live kernel-sized signal mask word.
        let ready = unsafe {
            crabc_core::event::epoll_pwait_raw(
                epoll.as_raw_fd(),
                events.cast(),
                maxevents,
                timeout,
                sigmask,
                crabc_core::signal::KERNEL_SIGSET_SIZE,
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

/// One 64-bit Linux/AArch64 `select` descriptor-set storage element.
///
/// The element is intentionally a transparent native value rather than the
/// public C `fd_set` wrapper. Use [`fd_set_num_elements`] to allocate enough
/// elements for a selected `nfds` range, then use the set helpers to mutate
/// and inspect the bit vector.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FdSetElement(u64);

const FD_SET_BITS: usize = size_of::<FdSetElement>() * 8;

/// Sets `fd` in a Linux descriptor bit vector.
#[doc(alias = "FD_SET")]
#[inline]
pub fn fd_set_insert(fds: &mut [FdSetElement], fd: crate::RawFd) {
    let fd = fd as usize;
    fds[fd / FD_SET_BITS].0 |= 1 << (fd % FD_SET_BITS);
}

/// Clears `fd` in a Linux descriptor bit vector.
#[doc(alias = "FD_CLR")]
#[inline]
pub fn fd_set_remove(fds: &mut [FdSetElement], fd: crate::RawFd) {
    let fd = fd as usize;
    fds[fd / FD_SET_BITS].0 &= !(1 << (fd % FD_SET_BITS));
}

/// Computes the smallest `nfds` value which includes every set bit in `fds`.
#[inline]
pub fn fd_set_bound(fds: &[FdSetElement]) -> crate::RawFd {
    if let Some(position) = fds.iter().rposition(|element| element.0 != 0) {
        let element = fds[position].0;
        (position * FD_SET_BITS + (FD_SET_BITS - element.leading_zeros() as usize)) as crate::RawFd
    } else {
        0
    }
}

/// Computes the number of descriptor-set elements needed for `nfds` bits.
///
/// `set_count` is retained for Rustix source compatibility and is ignored by
/// Linux's dense bit-vector representation.
#[inline]
pub const fn fd_set_num_elements(set_count: usize, nfds: crate::RawFd) -> usize {
    let _ = set_count;
    let nfds = nfds as usize;
    nfds.div_ceil(FD_SET_BITS)
}

/// Iterates over the set descriptor numbers in ascending order.
#[doc(alias = "FD_ISSET")]
pub struct FdSetIter<'a> {
    current: crate::RawFd,
    fds: &'a [FdSetElement],
}

impl<'a> FdSetIter<'a> {
    /// Constructs an iterator over `fds`.
    #[inline]
    pub fn new(fds: &'a [FdSetElement]) -> Self {
        Self { current: 0, fds }
    }
}

impl Iterator for FdSetIter<'_> {
    type Item = crate::RawFd;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(element) = self.fds.get(self.current as usize / FD_SET_BITS) {
            let shifted = element.0 >> (self.current as usize % FD_SET_BITS);
            if shifted != 0 {
                let fd = self.current + shifted.trailing_zeros() as crate::RawFd;
                self.current = fd + 1;
                return Some(fd);
            }

            if let Some(index) = self.fds[(self.current as usize / FD_SET_BITS) + 1..]
                .iter()
                .position(|element| element.0 != 0)
            {
                let index = index + (self.current as usize / FD_SET_BITS) + 1;
                let element = self.fds[index].0;
                let fd = (index * FD_SET_BITS) as crate::RawFd
                    + element.trailing_zeros() as crate::RawFd;
                self.current = fd + 1;
                return Some(fd);
            }
        }
        None
    }
}

/// Waits for readiness in Linux descriptor bit vectors.
///
/// The sets are rewritten by Linux to contain only ready descriptors. Each
/// supplied set must contain at least `fd_set_num_elements(0, nfds)` elements.
/// This function is unsafe because Rust cannot prove that every raw descriptor
/// in the sets stays open for the complete syscall; callers must also honor
/// the returned-set mutation contract.
///
/// The timeout is copied before crossing the kernel boundary, so Linux's
/// mutable `pselect6` timeout does not alter the caller's `Timespec`.
pub unsafe fn select(
    nfds: i32,
    readfds: Option<&mut [FdSetElement]>,
    writefds: Option<&mut [FdSetElement]>,
    exceptfds: Option<&mut [FdSetElement]>,
    timeout: Option<&Timespec>,
) -> Result<i32> {
    unsafe { pselect(nfds, readfds, writefds, exceptfds, timeout, None) }
}

/// Waits for readiness while temporarily installing a signal mask.
///
/// This is the native Rust extension corresponding to C `pselect`. Its
/// descriptor sets are the Rustix-compatible bit-vector slices, and the mask
/// is the borrowed kernel-sized [`SignalSet`]. The sets are rewritten by
/// Linux. The timeout is copied and the signal mask is atomically restored by
/// the kernel before return.
///
/// # Safety
///
/// Every descriptor represented by a supplied set must remain open for the
/// syscall's duration, and every set must have at least
/// `fd_set_num_elements(0, nfds)` elements. The mutable slices must remain
/// valid while Linux writes the resulting ready sets.
pub unsafe fn pselect(
    nfds: i32,
    readfds: Option<&mut [FdSetElement]>,
    writefds: Option<&mut [FdSetElement]>,
    exceptfds: Option<&mut [FdSetElement]>,
    timeout: Option<&Timespec>,
    mask: Option<&SignalSet>,
) -> Result<i32> {
    let required = fd_set_num_elements(0, nfds);
    let readfds = readfds.map(|fds| {
        assert!(fds.len() >= required);
        fds.as_mut_ptr().cast()
    });
    let writefds = writefds.map(|fds| {
        assert!(fds.len() >= required);
        fds.as_mut_ptr().cast()
    });
    let exceptfds = exceptfds.map(|fds| {
        assert!(fds.len() >= required);
        fds.as_mut_ptr().cast()
    });
    let mut timeout = timeout.copied();
    let timeout = timeout
        .as_mut()
        .map_or(core::ptr::null_mut(), |timeout| {
            (timeout as *mut Timespec).cast()
        });
    let sigmask = mask.map_or(core::ptr::null(), |mask| {
        (mask.kernel_bits() as *const u64).cast()
    });
    // SAFETY: The function's caller owns the set lifetime and descriptor
    // liveness obligations; local timeout and pselect6 argument records live
    // through the direct syscall.
    unsafe {
        crabc_core::event::pselect6_raw(
            nfds,
            readfds.unwrap_or(core::ptr::null_mut()),
            writefds.unwrap_or(core::ptr::null_mut()),
            exceptfds.unwrap_or(core::ptr::null_mut()),
            timeout,
            sigmask,
            crabc_core::signal::KERNEL_SIGSET_SIZE,
        )
    }
}

/// Waits for events on descriptor records while temporarily installing a
/// signal mask.
///
/// `None` waits indefinitely. A supplied timeout is copied before crossing
/// the kernel boundary because Linux may mutate its `ppoll` timespec. When
/// `mask` is `Some`, Linux atomically installs that borrowed [`SignalSet`]
/// during the wait and restores the calling thread's previous mask before
/// returning. The mask remains borrowed for the complete direct syscall and
/// is passed with Linux/AArch64's exact eight-byte kernel signal-set size.
#[inline]
pub fn ppoll(
    fds: &mut [PollFd<'_>],
    timeout: Option<&Timespec>,
    mask: Option<&SignalSet>,
) -> Result<usize> {
    let timeout = timeout.copied();
    let timeout = timeout
        .as_ref()
        .map_or(core::ptr::null(), |value| (value as *const Timespec).cast());
    let sigmask: *const u8 = mask.map_or(core::ptr::null(), |mask| {
        (mask.kernel_bits() as *const u64).cast()
    });
    // SAFETY: `PollFd` is exactly the Linux/AArch64 `pollfd` layout. Its
    // descriptor borrows keep every non-token descriptor open for the call;
    // `SignalSet` supplies one live Linux/AArch64 kernel signal-set word, and
    // the timeout copy remains live for the call.
    unsafe {
        crabc_core::event::ppoll_raw(
            fds.as_mut_ptr().cast(),
            fds.len(),
            timeout,
            sigmask,
            crabc_core::signal::KERNEL_SIGSET_SIZE,
        )
    }
}

/// Sleeps until a signal interrupts the calling thread.
///
/// Rustix exposes `pause` as a unit-returning operation because POSIX/Linux
/// only ever completes it by returning `EINTR`. Linux/AArch64 has no useful
/// standalone `pause` syscall for this facade's direct ABI, so use syscall 73
/// with the exact null `ppoll(NULL, 0, NULL, NULL)` arguments. The null mask
/// and its zero size leave the calling thread's signal mask unchanged.
#[inline]
pub fn pause() {
    // SAFETY: Null pointers and zero descriptor count are the intentional
    // kernel ABI for an indefinite signal-only ppoll wait.
    let result = unsafe {
        crabc_core::event::ppoll_raw(ptr::null_mut(), 0, ptr::null(), ptr::null(), 0)
    };
    debug_assert_eq!(result, Err(crate::Errno::INTR));
}

/// Waits for events on descriptor records without changing a signal mask.
///
/// `None` waits indefinitely. A supplied timeout is copied before crossing
/// the kernel boundary, so a kernel ABI implementation cannot mutate the
/// caller's immutable value. This preserves the existing unmasked [`poll`]
/// behavior while sharing the typed direct-`ppoll` implementation.
#[inline]
pub fn poll(fds: &mut [PollFd<'_>], timeout: Option<&Timespec>) -> Result<usize> {
    ppoll(fds, timeout, None)
}
