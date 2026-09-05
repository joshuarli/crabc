//! Owned DNS cancellation and descriptor retirement, source-mapped from musl
//! 1.2.6 release `9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT).
//! `src/network/res_msend.c::{__res_msend_rc,cleanup,start_tcp}` supply the
//! disabled acquisition/cleanup transaction and TCP fast-open ordering;
//! `sendto.c`, `sendmsg.c`, `recvmsg.c`, and `src/select/poll.c` supply actual
//! syscall cancellation boundaries. `src/thread/pthread_cancel.c::__cancel`
//! supplies MASKED -> DISABLE with ECANCELED. See
//! `compat/x86_64/owned-resolver-cancellation.md` for the source/license map.
//!
//! The shared core still owns DNS framing, parsing, deadlines and retries.
//! Its one-live-socket invariant replaces musl's parallel descriptor array.
//! The registered descriptor and CleanupNode are separately pinned stack
//! storage. Cancellation explicitly closes the descriptor through the C
//! cleanup chain; no Rust destructor, unwind, lock, or allocation participates.

use core::{cell::Cell, ffi::{c_int, c_void}, mem::MaybeUninit, ptr};
use crabc_core::{Errno, resolver::{self, DnsDatagram, DnsIoResult, DnsSocketAddress,
    DnsSocketKind, DnsTcpFailure, DnsTcpStart, DnsTransport, DnsWait, ExchangeConfig, ExchangeError}};
use super::{pthread_cancel, raw_syscall};

const DISABLE: c_int = 1;
const MASKED: c_int = 2;
const MSG_NOSIGNAL: i64 = 0x4000;
const MSG_FASTOPEN: i64 = 0x2000_0000;
const MSG_TRUNC: i64 = 0x20;

#[repr(C)]
struct PollFd { fd: c_int, events: i16, revents: i16 }
#[repr(C)]
struct Iovec { base: *mut u8, length: usize }
#[repr(C)]
struct Message {
    name: *const u8, name_length: u32, iovecs: *const Iovec, iovec_count: usize,
    control: *mut c_void, control_length: usize, flags: c_int,
}
const _: () = assert!(core::mem::size_of::<PollFd>() == 8);
const _: () = assert!(core::mem::size_of::<Iovec>() == 16);
const _: () = assert!(core::mem::size_of::<Message>() == 56);
const _: () = assert!(core::mem::offset_of!(Message, iovecs) == 16);
const _: () = assert!(core::mem::offset_of!(Message, flags) == 48);

impl Message {
    fn connected(iovecs: &[Iovec]) -> Self {
        Self { name: ptr::null(), name_length: 0, iovecs: iovecs.as_ptr(),
            iovec_count: iovecs.len(), control: ptr::null_mut(), control_length: 0, flags: 0 }
    }
}

struct CleanupDescriptor { fd: Cell<c_int> }

/// # Safety
/// `argument` points to the pinned CleanupDescriptor registered by `exchange`.
/// It remains live through C cleanup retirement, and this thread is its only
/// mutator. The current owned cleanup drain has disabled cancellation.
unsafe extern "C" fn cleanup(argument: *mut c_void) {
    let descriptor = unsafe { &*argument.cast::<CleanupDescriptor>() };
    let fd = descriptor.fd.replace(-1);
    if fd >= 0 { unsafe { raw_syscall::syscall1(3, fd as i64); } }
}

struct OwnedDnsTransport<'a> {
    descriptor: &'a CleanupDescriptor,
    entry_state: c_int,
    resume_state: c_int,
    consumed_masked: bool,
    last_errno: Option<Errno>,
}

impl OwnedDnsTransport<'_> {
    fn record(&mut self, result: i64) -> crabc_core::Result<usize> {
        if result < 0 {
            let error = Errno::from_raw((-result) as c_int).unwrap_or(Errno::IO);
            self.last_errno = Some(error);
            Err(error)
        } else { Ok(result as usize) }
    }

    /// # Safety
    /// Arguments meet the named syscall's initialized pointer/range/lifetime
    /// contract. The descriptor is registered in the pinned C cleanup node;
    /// callers hold no resource requiring Rust unwinding at this boundary.
    unsafe fn cp(&mut self, number: i64, arguments: [i64;6]) -> DnsIoResult<usize> {
        let resumed = self.resume_state;
        unsafe { pthread_cancel::pthread_setcancelstate(resumed, ptr::null_mut()); }
        let [a,b,c,d,e,f] = arguments;
        let result = unsafe { pthread_cancel::syscall_cp(number,a,b,c,d,e,f) };
        let mut actual = DISABLE;
        unsafe { pthread_cancel::pthread_setcancelstate(DISABLE, &mut actual); }
        self.resume_state = actual;
        let decoded = self.record(result);
        // A kernel or seccomp ECANCELED alone is not a cancellation event.
        // The owned cancellation window must also have consumed MASKED state.
        if resumed == MASKED && actual == DISABLE && result == -(Errno::CANCELED.raw() as i64) {
            self.consumed_masked = true;
            DnsIoResult::MaskedCancellation
        } else { decoded.into() }
    }
}

impl DnsTransport for OwnedDnsTransport<'_> {
    fn socket_opened(&mut self, fd: c_int, _kind: DnsSocketKind) {
        // Core reports acquisition while cancellation is disabled and before
        // the next CP. Cell gives cleanup shared interior access without an
        // alias to this transport's live mutable borrow at a retiring syscall.
        self.descriptor.fd.set(fd);
    }

    fn close_socket(&mut self, fd: c_int) {
        self.descriptor.fd.set(-1);
        unsafe { raw_syscall::syscall1(3, fd as i64); }
    }

    fn syscall_failed(&mut self, error: Errno) { self.last_errno = Some(error); }

    fn stream_starting(&mut self) -> DnsTcpFailure {
        // The original entry state resumes after the disabled source TCP-start
        // phase even if its first socket acquisition fails. Its outer poll is
        // still a real CP with no active events until the same query deadline.
        self.resume_state = self.entry_state;
        DnsTcpFailure::WaitUntilDeadline
    }

    fn wait(&mut self, fd: c_int, event: DnsWait, timeout_ms: u32) -> DnsIoResult<bool> {
        let events = match event { DnsWait::Readable => 1, DnsWait::Writable => 4 };
        let mut poll = PollFd { fd, events, revents: 0 };
        // SAFETY: one writable pollfd remains live through the actual source
        // poll CP. Owned resolver configuration bounds timeouts to 30 seconds.
        match unsafe { self.cp(7, [&mut poll as *mut PollFd as i64, 1,
            timeout_ms.min(c_int::MAX as u32) as i64, 0, 0, 0]) } {
            DnsIoResult::Complete(count) => DnsIoResult::Complete(count != 0 && poll.revents & (events|8|16|32) != 0),
            DnsIoResult::Failed(error) => DnsIoResult::Failed(error),
            DnsIoResult::MaskedCancellation => DnsIoResult::MaskedCancellation,
        }
    }

    fn send(&mut self, fd: c_int, bytes: &[u8], kind: DnsSocketKind) -> DnsIoResult<usize> {
        if kind == DnsSocketKind::Datagram {
            // SAFETY: connected UDP send with exactly the borrowed readable
            // query, no destination pointer, and a registered descriptor.
            unsafe { self.cp(44, [fd as i64, bytes.as_ptr() as i64, bytes.len() as i64, MSG_NOSIGNAL, 0, 0]) }
        } else {
            let iovecs = [Iovec { base: bytes.as_ptr().cast_mut(), length: bytes.len() }];
            let message = Message::connected(&iovecs);
            // SAFETY: the initialized header/iovec borrow the readable stream
            // suffix for the actual source sendmsg cancellation point.
            unsafe { self.cp(46, [fd as i64, &message as *const Message as i64, MSG_NOSIGNAL, 0, 0, 0]) }
        }
    }

    fn receive_stream(&mut self, fd: c_int, bytes: &mut [u8]) -> DnsIoResult<usize> {
        let iovecs = [Iovec { base: bytes.as_mut_ptr(), length: bytes.len() }];
        let mut message = Message::connected(&iovecs);
        // SAFETY: the header is writable and its one iovec covers exactly the
        // exclusive caller buffer; all remain live through the recvmsg CP.
        unsafe { self.cp(47, [fd as i64, &mut message as *mut Message as i64, 0, 0, 0, 0]) }
    }

    fn receive_datagram(&mut self, fd: c_int, bytes: &mut [u8]) -> DnsIoResult<DnsDatagram> {
        let iovecs = [Iovec { base: bytes.as_mut_ptr(), length: bytes.len() }];
        let mut message = Message::connected(&iovecs);
        // SAFETY: as above, with MSG_TRUNC preserving the shared core's
        // existing full-packet length/overflow boundary.
        match unsafe { self.cp(47, [fd as i64, &mut message as *mut Message as i64, MSG_TRUNC, 0, 0, 0]) } {
            DnsIoResult::Complete(length) => DnsIoResult::Complete(DnsDatagram { length, truncated: message.flags & MSG_TRUNC as c_int != 0 }),
            DnsIoResult::Failed(error) => DnsIoResult::Failed(error),
            DnsIoResult::MaskedCancellation => DnsIoResult::MaskedCancellation,
        }
    }

    fn start_tcp(&mut self, fd: c_int, target: &DnsSocketAddress, query: &[u8], _deadline: i64) -> crabc_core::Result<DnsTcpStart> {
        // Source start_tcp is wholly disabled. Its original-entry-state
        // restoration is distinct from ordinary CP post-state preservation.
        let address = target.as_bytes();
        let enabled: c_int = 1;
        // SAFETY: the initialized int option and sockaddr remain live through
        // their raw non-canceling operations; fd is registered for retirement.
        let option = unsafe { raw_syscall::syscall5(54, fd as i64, 6, 30,
            &enabled as *const c_int as i64, core::mem::size_of::<c_int>() as i64) };
        if self.record(option).is_ok() {
            let prefix = [(query.len() >> 8) as u8, query.len() as u8];
            let iovecs = [Iovec { base: prefix.as_ptr().cast_mut(), length: 2 },
                Iovec { base: query.as_ptr().cast_mut(), length: query.len() }];
            let mut message = Message::connected(&iovecs);
            message.name = address.as_ptr(); message.name_length = address.len() as u32;
            // SAFETY: both readable frame slices and the addressed header are
            // initialized locals. Source sends this first frame with cancel
            // disabled; later queued suffixes use the ordinary sendmsg CP.
            let sent = unsafe { raw_syscall::syscall3(46, fd as i64,
                &message as *const Message as i64, MSG_FASTOPEN|MSG_NOSIGNAL) };
            match self.record(sent) {
                Ok(frame_bytes) => return Ok(DnsTcpStart::Queued { frame_bytes }),
                Err(error) if error == Errno::INPROGRESS => return Ok(DnsTcpStart::Queued { frame_bytes: 0 }),
                Err(_) => (),
            }
        }
        let connected = unsafe { raw_syscall::syscall3(42, fd as i64, address.as_ptr() as i64, address.len() as i64) };
        match self.record(connected) {
            Ok(_) => Ok(DnsTcpStart::Queued { frame_bytes: 0 }),
            Err(error) if error == Errno::INPROGRESS => Ok(DnsTcpStart::Queued { frame_bytes: 0 }),
            Err(error) => Err(error),
        }
    }
}

pub(super) struct ExchangeOutcome {
    pub result: Result<usize, ExchangeError>,
    /// Present only after actual MASKED consumption. Later syscall errors may
    /// supersede ECANCELED; the caller must preserve this actual final errno.
    pub masked_errno: Option<c_int>,
}

/// Execute shared DNS transport with an explicit owned C cancellation owner.
/// # Safety
/// The current thread has an initialized owned TCB. Callers hold no lock or
/// unregistered resource whose retirement requires Rust stack unwinding.
/// Query/answer storage remains valid until normal return or thread retirement.
pub(super) unsafe fn exchange(config: &ExchangeConfig, query: &[u8], query_id: u16, answer: &mut [u8]) -> ExchangeOutcome {
    let mut entry_state = DISABLE;
    unsafe { pthread_cancel::pthread_setcancelstate(DISABLE, &mut entry_state); }
    let descriptor = core::pin::pin!(CleanupDescriptor { fd: Cell::new(-1) });
    let mut node = core::pin::pin!(MaybeUninit::<pthread_cancel::CleanupNode>::uninit());
    let node_pointer = node.as_mut().get_mut().as_mut_ptr();
    let descriptor = descriptor.as_ref().get_ref();
    // SAFETY: both pinned stack allocations remain at these exact addresses
    // until matching pop or C cleanup retirement; the callback shares only
    // the descriptor Cell, not a mutable transport borrow.
    unsafe { pthread_cancel::_pthread_cleanup_push(node_pointer, Some(cleanup),
        (descriptor as *const CleanupDescriptor).cast_mut().cast()); }
    let mut transport = OwnedDnsTransport { descriptor, entry_state, resume_state: entry_state,
        consumed_masked: false, last_errno: None };
    let result = resolver::exchange_with_transport(config, query, query_id, answer, &mut transport);
    // Core returned with cancellation disabled and no live descriptor. Pop
    // explicitly, then restore the actual final state rather than entry state.
    unsafe { pthread_cancel::_pthread_cleanup_pop(node_pointer, 0);
        pthread_cancel::pthread_setcancelstate(transport.resume_state, ptr::null_mut()); }
    ExchangeOutcome { result, masked_errno: if transport.consumed_masked {
        transport.last_errno.map(Errno::raw)
    } else { None } }
}
