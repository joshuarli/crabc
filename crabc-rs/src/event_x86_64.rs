//! The deliberately narrow Linux/x86-64 event facade.
//!
//! This target admits the scalar `eventfd2` counter seam and typed `poll(2)`,
//! `ppoll(2)`, `select(2)`, `pselect(2)`, signal-only `pause`, and epoll
//! readiness operations. The descriptor-set records and pselect signal-mask
//! pair stay target-specific: this module never reuses an AArch64 record or
//! claims a public C polling ABI. Signalfd remains absent until it has
//! independent x86-64 evidence.

use core::convert::TryFrom;
use core::ffi::c_void;
use core::hash::{Hash, Hasher};
use core::mem::size_of;
use core::ptr;

use bitflags::bitflags;

use crate::buffer::Buffer;
use crate::signal::SignalSet;
pub use crate::time::Timespec;
use crate::{AsFd, BorrowedFd, OwnedFd, Result};

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
            /// Preserve future Linux-defined bits for kernel validation.
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
            /// `EPOLLPRI`.
            const PRI = 0x0000_0002;
            /// `EPOLLOUT`.
            const OUT = 0x0000_0004;
            /// `EPOLLERR`.
            const ERR = 0x0000_0008;
            /// `EPOLLHUP`.
            const HUP = 0x0000_0010;
            /// `EPOLLNVAL`.
            const NVAL = 0x0000_0020;
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
            /// `EPOLLONESHOT`.
            const ONESHOT = 0x4000_0000;
            /// `EPOLLEXCLUSIVE`.
            const EXCLUSIVE = 0x1000_0000;
            /// `EPOLLWAKEUP`.
            const WAKEUP = 0x2000_0000;
            /// `EPOLLET`.
            const ET = 0x8000_0000;
            /// Preserve future Linux-defined bits reported by or forwarded to
            /// the kernel.
            const _ = !0;
        }
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

    impl core::fmt::Debug for EventData {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.debug_tuple("EventData").field(&self.u64()).finish()
        }
    }

    /// One Linux/x86-64 `struct epoll_event` record.
    ///
    /// x86-64 uses the packed 12-byte kernel layout: the 32-bit event mask at
    /// offset zero followed immediately by the 64-bit data union at offset
    /// four. Fields are private so callers cannot accidentally take an
    /// unaligned reference; use [`Self::flags`] and [`Self::data`] instead.
    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct Event {
        flags: EventFlags,
        data: EventData,
    }

    const _: () = assert!(size_of::<Event>() == 12);
    const _: () = assert!(core::mem::align_of::<Event>() == 1);
    const _: () = assert!(core::mem::offset_of!(Event, flags) == 0);
    const _: () = assert!(core::mem::offset_of!(Event, data) == 4);

    impl Event {
        /// Constructs an event record for an epoll registration or result.
        #[inline]
        pub const fn new(flags: EventFlags, data: EventData) -> Self {
            Self { flags, data }
        }

        /// Returns readiness and behavior flags from this event.
        #[inline]
        pub fn flags(self) -> EventFlags {
            self.flags
        }

        /// Returns caller-provided data from this event.
        #[inline]
        pub fn data(self) -> EventData {
            self.data
        }
    }

    impl PartialEq for Event {
        #[inline]
        fn eq(&self, other: &Self) -> bool {
            self.flags() == other.flags() && self.data() == other.data()
        }
    }

    impl Eq for Event {}

    impl Hash for Event {
        #[inline]
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.flags().hash(state);
            self.data().hash(state);
        }
    }

    impl core::fmt::Debug for Event {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("Event")
                .field("flags", &self.flags())
                .field("data", &self.data())
                .finish()
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

    /// Creates an epoll descriptor using the legacy positive-size contract.
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
        ctl(epoll, source, 1, Event::new(event_flags, data))
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
        ctl(epoll, source, 3, Event::new(event_flags, data))
    }

    fn ctl<EpollFd: AsFd, SourceFd: AsFd>(
        epoll: EpollFd,
        source: SourceFd,
        operation: u32,
        event: Event,
    ) -> Result<()> {
        let epoll = epoll.as_fd();
        let source = source.as_fd();
        // SAFETY: `Event` has the exact packed x86-64 epoll layout and lives
        // through the syscall; both descriptor borrows remain open as well.
        unsafe {
            crabc_core::event::epoll_ctl_raw(
                epoll.as_raw_fd(),
                operation,
                source.as_raw_fd(),
                (&event as *const Event).cast::<crabc_core::event::KernelEpollEvent>(),
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
                ptr::null(),
            )
        }
    }

    /// Waits for registered events, initializing the supplied event buffer.
    ///
    /// `timeout` is rounded up to Linux's signed millisecond representation.
    /// Invalid timespec fields and values which do not fit that representation
    /// return [`crate::Errno::INVAL`].
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
    /// `timeout` is rounded up to Linux's signed millisecond representation.
    /// A supplied mask is installed atomically for the wait and restored by the
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
        // The Linux ABI takes this count as a signed `int`; reject values
        // which cannot be represented before crossing the raw seam.
        let maxevents = i32::try_from(maxevents).map_err(|_| crate::Errno::INVAL)?;
        let sigmask = mask.map_or(ptr::null(), |mask| {
            (mask.kernel_bits() as *const u64).cast()
        });
        // SAFETY: `Buffer` supplies writable storage for `maxevents` packed
        // x86-64 records, the epoll descriptor remains open for the call, and
        // `SignalSet` supplies one live kernel-sized signal-mask word.
        let ready = unsafe {
            crabc_core::event::epoll_pwait_raw(
                epoll.as_raw_fd(),
                events.cast::<crabc_core::event::KernelEpollEvent>(),
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
}

/// One 64-bit Linux/x86-64 `select` descriptor-set storage element.
///
/// The element is intentionally a transparent native value rather than a
/// public C `fd_set` wrapper. Use [`fd_set_num_elements`] to allocate enough
/// elements for a selected `nfds` range, then use the set helpers to mutate
/// and inspect the bit vector. Linux's x86-64 kernel representation is one
/// little-endian 64-bit word per element.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FdSetElement(u64);

const FD_SET_BITS: usize = size_of::<FdSetElement>() * 8;

const _: () = assert!(size_of::<FdSetElement>() == 8);
const _: () = assert!(core::mem::align_of::<FdSetElement>() == 8);

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
/// Negative `nfds` and undersized sets are rejected with [`crate::Errno::INVAL`]
/// before any pointer is formed or the kernel is entered.
///
/// # Safety
///
/// Every descriptor represented by a supplied set must remain open for the
/// syscall's duration. Supplied mutable sets must remain valid and writable;
/// their first `fd_set_num_elements(0, nfds)` elements are rewritten by Linux.
pub unsafe fn select(
    nfds: i32,
    readfds: Option<&mut [FdSetElement]>,
    writefds: Option<&mut [FdSetElement]>,
    exceptfds: Option<&mut [FdSetElement]>,
    timeout: Option<&Timespec>,
) -> Result<i32> {
    // SAFETY: `select` has exactly the unmasked pselect contract and does not
    // add any pointer or descriptor obligations of its own.
    unsafe { pselect(nfds, readfds, writefds, exceptfds, timeout, None) }
}

/// Waits for readiness while temporarily installing a signal mask.
///
/// This is the native Rust extension corresponding to C `pselect`. Its
/// descriptor sets are Rustix-compatible bit-vector slices, and the mask is
/// the borrowed kernel-sized [`SignalSet`]. Linux rewrites each supplied set
/// to contain only ready descriptors. The timeout is copied, and the signal
/// mask is atomically restored by the kernel before return.
///
/// Negative `nfds` and undersized sets are rejected with
/// [`crate::Errno::INVAL`] rather than panicking. The x86-64 kernel signal
/// mask is passed as one eight-byte word, even though the public musl
/// `sigset_t` has a wider C representation.
///
/// # Safety
///
/// Every descriptor represented by a supplied set must remain open for the
/// syscall's duration. Supplied mutable sets must remain valid and writable;
/// their first `fd_set_num_elements(0, nfds)` elements are rewritten by Linux.
pub unsafe fn pselect(
    nfds: i32,
    readfds: Option<&mut [FdSetElement]>,
    writefds: Option<&mut [FdSetElement]>,
    exceptfds: Option<&mut [FdSetElement]>,
    timeout: Option<&Timespec>,
    mask: Option<&SignalSet>,
) -> Result<i32> {
    if nfds < 0 {
        return Err(crate::Errno::INVAL);
    }
    let required = fd_set_num_elements(0, nfds);
    let readfds = match readfds {
        Some(fds) if fds.len() < required => return Err(crate::Errno::INVAL),
        Some(fds) => Some(fds.as_mut_ptr().cast()),
        None => None,
    };
    let writefds = match writefds {
        Some(fds) if fds.len() < required => return Err(crate::Errno::INVAL),
        Some(fds) => Some(fds.as_mut_ptr().cast()),
        None => None,
    };
    let exceptfds = match exceptfds {
        Some(fds) if fds.len() < required => return Err(crate::Errno::INVAL),
        Some(fds) => Some(fds.as_mut_ptr().cast()),
        None => None,
    };
    let mut timeout = timeout.copied();
    let timeout = timeout
        .as_mut()
        .map_or(ptr::null_mut(), |value| (value as *mut Timespec).cast());
    let sigmask = mask.map_or(ptr::null(), |mask| (mask.kernel_bits() as *const u64).cast());
    // SAFETY: The function's caller owns descriptor-set liveness and the
    // pointed-to set storage. The local timeout and the borrowed signal mask
    // remain live for the complete direct syscall. The core seam owns the
    // x86-64 pselect6 argument-6 pair and uses the eight-byte mask size.
    unsafe {
        crabc_core::event::pselect6_raw(
            nfds,
            readfds.unwrap_or(ptr::null_mut()),
            writefds.unwrap_or(ptr::null_mut()),
            exceptfds.unwrap_or(ptr::null_mut()),
            timeout,
            sigmask,
            crabc_core::signal::KERNEL_SIGSET_SIZE,
        )
    }
}

/// Waits for descriptor readiness while temporarily installing a signal mask.
///
/// `None` waits indefinitely. The supplied timeout is copied before crossing
/// the kernel boundary because Linux may mutate the `ppoll` timespec. When
/// `mask` is `Some`, Linux atomically installs that borrowed [`SignalSet`]
/// during the wait and restores the calling thread's previous mask before
/// returning. The mask remains borrowed for the complete direct syscall and
/// is passed with Linux/x86-64's exact eight-byte kernel signal-set size.
#[inline]
pub fn ppoll(
    fds: &mut [PollFd<'_>],
    timeout: Option<&Timespec>,
    mask: Option<&SignalSet>,
) -> Result<usize> {
    let timeout = timeout.copied();
    let timeout = timeout
        .as_ref()
        .map_or(ptr::null(), |value| (value as *const Timespec).cast());
    let sigmask: *const u8 = mask.map_or(ptr::null(), |mask| {
        (mask.kernel_bits() as *const u64).cast()
    });
    // SAFETY: `PollFd` is exactly the Linux/x86-64 `pollfd` layout. Its
    // descriptor borrows keep every descriptor open for the call;
    // `SignalSet` supplies one live Linux/x86-64 kernel signal-set word, and
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
/// Linux/x86-64 has a dedicated `pause(2)` syscall, but the direct facade
/// keeps this operation on the existing `ppoll` seam so its signal-mask and
/// interruption behavior share one kernel boundary. The null mask and zero
/// size leave the calling thread's signal mask unchanged.
#[inline]
pub fn pause() {
    // SAFETY: Null pointers and zero descriptor count are the intentional
    // kernel ABI for an indefinite signal-only ppoll wait.
    let result =
        unsafe { crabc_core::event::ppoll_raw(ptr::null_mut(), 0, ptr::null(), ptr::null(), 0) };
    debug_assert_eq!(result, Err(crate::Errno::INTR));
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
