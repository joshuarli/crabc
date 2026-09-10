//! The selected x86 C resolver's one/two-query source batch, mapped to musl
//! 1.2.6 `src/network/res_msend.c::{__res_msend_rc,cleanup,start_tcp}` (MIT,
//! release `9fa28ece75d8a2191de7c5bb53bed224c5947417`).  This is deliberately
//! separate from `owned_resolver_transport`: the latter retains the strict
//! one-live-descriptor `crabc_core::resolver::DnsTransport` contract used by
//! native Rust and frozen AArch64 paths. `CResolverBatchConfig` copies the C
//! resolver state into a separately named total retry clock; core's
//! per-server `ExchangeConfig::timeout_ms` interpretation is unchanged.
//!
//! The receipt proves only source, ID, header and exactly-one echoed-question
//! association.  It does not publish parsed records.  UDP `MSG_TRUNC` now
//! starts TCP for this selected C batch after that bounded-prefix association,
//! while TCP still requires one complete declared frame fitting the caller's
//! buffer.  Both exact association and the bounded complete TCP frame are
//! intentional stronger project boundaries recorded with the owning fixtures.

use core::{cell::Cell, ffi::{c_int, c_void}, marker::PhantomData, mem::MaybeUninit, ptr};
use crabc_core::{Errno, resolver::{ExchangeConfig, ExchangeError, NameServer}};
use super::{pthread_cancel, raw_syscall};

const DISABLE: c_int = 1;
const MASKED: c_int = 2;
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const SOCK_STREAM: i64 = 1;
const SOCK_DGRAM: i64 = 2;
const SOCK_NONBLOCK: i64 = 0x800;
const SOCK_CLOEXEC: i64 = 0x80000;
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const MSG_NOSIGNAL: i64 = 0x4000;
const MSG_FASTOPEN: i64 = 0x2000_0000;
const MSG_TRUNC: c_int = 0x20;
const TCP_FASTOPEN_CONNECT: i64 = 30;
const IPV6_V6ONLY: i64 = 26;

#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd { fd: c_int, events: i16, revents: i16 }
#[repr(C)]
#[derive(Clone, Copy)]
struct Iovec { base: *mut u8, length: usize }
#[repr(C)]
struct Message {
    name: *const u8, name_length: u32, iovecs: *const Iovec, iovec_count: usize,
    control: *mut c_void, control_length: usize, flags: c_int,
}
#[repr(C)]
struct Timespec { seconds: i64, nanoseconds: i64 }
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

/// One caller-owned query/reply slot.  The batch admits exactly one or two
/// slots and rejects overlapping reply ranges before any descriptor exists.
pub(super) struct BatchRequest<'a> {
    query: &'a [u8],
    query_id: u16,
    answer: &'a mut [u8],
}

/// The C resolver's source-shaped batch configuration.  This type is the
/// explicit boundary that changes `timeout_ms` from core's per-server timeout
/// to `res_msend_rc`'s total elapsed-loop budget; no native transport accepts
/// or observes this interpretation.
#[derive(Clone, Copy)]
pub(super) struct CResolverBatchConfig {
    nameservers: [NameServer; 3],
    nameserver_count: usize,
    total_timeout_ms: u32,
    attempts: u8,
}

impl CResolverBatchConfig {
    pub(super) fn from_c_resolver(config: &ExchangeConfig) -> Self {
        Self { nameservers: config.nameservers, nameserver_count: config.nameserver_count,
            total_timeout_ms: config.timeout_ms, attempts: config.attempts }
    }
}

/// A closed source admission shape.  `lookup_name` and the selected raw C
/// resolver call sites can express musl's one or two request slots, but cannot
/// accidentally create a scheduler with a third or zero slot.
pub(super) enum BatchRequests<'a> {
    One(BatchRequest<'a>),
    Two(BatchRequest<'a>, BatchRequest<'a>),
}

impl<'a> BatchRequests<'a> {
    pub(super) fn one(request: BatchRequest<'a>) -> Self { Self::One(request) }
    pub(super) fn two(first: BatchRequest<'a>, second: BatchRequest<'a>) -> Self { Self::Two(first, second) }
}

impl<'a> BatchRequest<'a> {
    pub(super) fn new(query: &'a [u8], query_id: u16, answer: &'a mut [u8]) -> Self {
        Self { query, query_id, answer }
    }
}

/// Opaque lengths of source-associated replies.  A zero length is musl's
/// per-query unanswered result, including a TCP start that never obtained an
/// fd or a frame rejected by the project-complete TCP boundary.
pub(super) struct BatchReceipt { lengths: [usize; 2], count: usize }
impl BatchReceipt {
    pub(super) fn length(&self, index: usize) -> Option<usize> {
        self.lengths.get(index).copied().filter(|_| index < self.count)
    }
}

pub(super) struct BatchOutcome {
    pub result: Result<BatchReceipt, ExchangeError>,
    /// Last raw or cancellation-point errno observed by the source scheduler.
    /// Raw x86 syscalls do not publish C errno themselves, so selected C
    /// callers restore the same observable residue after the batch returns.
    pub last_errno: Option<c_int>,
    pub masked_errno: Option<c_int>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SlotState { PendingUdp, PendingTcp, Accepted(usize) }

/// Source's `next` is the first reusable UDP temporary buffer.  TCP mode has
/// already occupied its answer storage and must be skipped just like a
/// completed positive reply.
fn next_reusable(states: &[SlotState; 2], count: usize, mut next: usize) -> usize {
    while next < count && states[next] != SlotState::PendingUdp { next += 1; }
    next
}

#[cfg(test)]
mod scheduler_tests {
    use super::{common_answer_capacity, next_reusable, SlotState};

    #[test]
    fn tcp_pending_slot_is_not_a_udp_temporary_after_a_completing_a() {
        // AAAA (slot 1) first selected TCP.  A (slot 0) then completed; an
        // extra UDP datagram must never be received into slot 1 while its TCP
        // frame is in flight.
        let states = [SlotState::Accepted(42), SlotState::PendingTcp];
        assert_eq!(next_reusable(&states, 2, 0), 2);
    }

    #[test]
    fn two_slot_copy_requires_the_source_common_answer_capacity() {
        assert!(!common_answer_capacity(4800, 512));
        assert!(common_answer_capacity(4800, 4800));
    }
}

fn common_answer_capacity(first: usize, second: usize) -> bool { first == second }

#[derive(Clone, Copy)]
struct Slot {
    query: *const u8,
    query_length: usize,
    query_id: u16,
    answer: *mut u8,
    answer_length: usize,
    state: SlotState,
    qpos: usize,
    apos: usize,
    frame_length: [u8; 2],
}

impl Slot {
    unsafe fn query(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.query, self.query_length) }
    }
    unsafe fn answer(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.answer, self.answer_length) }
    }
}

#[derive(Clone, Copy)]
struct SocketAddress { bytes: [u8; 28], length: u32, family: c_int }

impl SocketAddress {
    fn from_server(server: NameServer) -> Option<Self> {
        let mut bytes = [0u8; 28];
        match server.family as c_int {
            AF_INET => {
                bytes[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
                bytes[2..4].copy_from_slice(&server.port.to_be_bytes());
                bytes[4..8].copy_from_slice(&server.address[..4]);
                Some(Self { bytes, length: 16, family: AF_INET })
            }
            AF_INET6 => {
                bytes[..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
                bytes[2..4].copy_from_slice(&server.port.to_be_bytes());
                bytes[8..24].copy_from_slice(&server.address);
                bytes[24..28].copy_from_slice(&server.scope_id.to_ne_bytes());
                Some(Self { bytes, length: 28, family: AF_INET6 })
            }
            _ => None,
        }
    }

    fn mapped_v4(self) -> Self {
        if self.family != AF_INET { return self; }
        let mut bytes = [0u8; 28];
        bytes[..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&self.bytes[2..4]);
        bytes[18] = 0xff; bytes[19] = 0xff;
        bytes[20..24].copy_from_slice(&self.bytes[4..8]);
        Self { bytes, length: 28, family: AF_INET6 }
    }
}

struct CleanupDescriptors { fds: [Cell<c_int>; 3] }
impl CleanupDescriptors {
    fn new() -> Self { Self { fds: core::array::from_fn(|_| Cell::new(-1)) } }
    fn close(&self, index: usize) {
        let fd = self.fds[index].replace(-1);
        if fd >= 0 { unsafe { raw_syscall::syscall1(3, fd as i64); } }
    }
}

/// # Safety
/// `argument` points to the pinned descriptor Cells of an active batch.  C
/// cleanup is the sole concurrent path and each Cell is cleared before close.
unsafe extern "C" fn cleanup(argument: *mut c_void) {
    let descriptors = unsafe { &*argument.cast::<CleanupDescriptors>() };
    for index in 0..3 { descriptors.close(index); }
}

enum Cp<T> { Complete(T), Failed(Errno), Masked }

struct Batch<'a> {
    slots: [Slot; 2],
    count: usize,
    servers: [SocketAddress; 3],
    server_count: usize,
    socket_family: c_int,
    config: &'a CResolverBatchConfig,
    descriptors: &'a CleanupDescriptors,
    entry_state: c_int,
    resume_state: c_int,
    consumed_masked: bool,
    last_errno: Option<Errno>,
    pfd: [PollFd; 3],
    next: usize,
}

impl Batch<'_> {
    fn record(&mut self, result: i64) -> Result<usize, Errno> {
        if result < 0 {
            let error = Errno::from_raw((-result) as c_int).unwrap_or(Errno::IO);
            self.last_errno = Some(error);
            Err(error)
        } else { Ok(result as usize) }
    }

    /// # Safety
    /// The syscall argument contracts hold and its descriptor is held in the
    /// separately pinned cleanup Cells through this cancellation point.
    unsafe fn cp(&mut self, number: i64, arguments: [i64; 6]) -> Cp<usize> {
        let resumed = self.resume_state;
        unsafe { pthread_cancel::pthread_setcancelstate(resumed, ptr::null_mut()); }
        let [a,b,c,d,e,f] = arguments;
        let result = unsafe { pthread_cancel::syscall_cp(number, a,b,c,d,e,f) };
        let mut actual = DISABLE;
        unsafe { pthread_cancel::pthread_setcancelstate(DISABLE, &mut actual); }
        self.resume_state = actual;
        match self.record(result) {
            Ok(value) => Cp::Complete(value),
            Err(error) if resumed == MASKED && actual == DISABLE
                && error == Errno::CANCELED => {
                    self.consumed_masked = true;
                    Cp::Masked
                }
            Err(error) => Cp::Failed(error),
        }
    }

    fn time_ms(&mut self) -> u64 {
        let mut time = Timespec { seconds: 0, nanoseconds: 0 };
        // Linux 5.10 supplies CLOCK_MONOTONIC.  The upstream ENOSYS realtime
        // fallback is intentionally omitted rather than adding pre-baseline
        // kernel behavior to this selected Linux runtime.
        let result = unsafe { raw_syscall::syscall2(228, 1, &mut time as *mut Timespec as i64) };
        if self.record(result).is_err() { return 0; }
        (time.seconds as u64).wrapping_mul(1000).wrapping_add((time.nanoseconds / 1_000_000) as u64)
    }

    fn raw(&mut self, number: i64, arguments: [i64; 6]) -> Result<usize, Errno> {
        let [a,b,c,d,e,f] = arguments;
        let result = unsafe { raw_syscall::syscall6(number, a,b,c,d,e,f) };
        self.record(result)
    }

    fn all_accepted(&self) -> bool {
        self.slots[..self.count].iter().all(|slot| matches!(slot.state, SlotState::Accepted(_)))
    }

    fn lengths(&self) -> [usize; 2] {
        core::array::from_fn(|index| if index < self.count {
            match self.slots[index].state { SlotState::Accepted(length) => length, _ => 0 }
        } else { 0 })
    }

    fn send_udp(&mut self, slot: usize, server: usize) {
        let query = unsafe { self.slots[slot].query() };
        let address = self.servers[server];
        // Source ignores every UDP send result, including MASKED ECANCELED.
        let _ = unsafe { self.cp(44, [self.pfd[self.count].fd as i64, query.as_ptr() as i64,
            query.len() as i64, MSG_NOSIGNAL, address.bytes.as_ptr() as i64,
            address.length as i64]) };
    }

    fn matching_reply(&self, slot: usize, packet: &[u8]) -> bool {
        let request = unsafe { self.slots[slot].query() };
        if packet.len() < 12 || request.len() < 12
            || packet[0..2] != self.slots[slot].query_id.to_be_bytes()
            || packet[2] & 0x80 == 0 || packet[2] & 0x78 != 0
            || packet[4] != 0 || packet[5] != 1 { return false; }
        let Some(request_end) = question_end(request, 12) else { return false; };
        let Some(reply_end) = question_end(packet, 12) else { return false; };
        request_end + 4 <= request.len() && reply_end + 4 <= packet.len()
            && request[12..request_end + 4] == packet[12..reply_end + 4]
    }

    fn source_server(&self, source: &[u8; 28], source_length: u32) -> Option<usize> {
        (0..self.server_count).find(|&index| {
            let address = self.servers[index];
            source_length == address.length && source[..address.length as usize] == address.bytes[..address.length as usize]
        })
    }

    fn start_tcp(&mut self, slot: usize, server: usize) {
        // Every source TCP start temporarily restores the original entry state
        // afterwards, even if a preceding CP consumed MASKED cancellation.
        unsafe { pthread_cancel::pthread_setcancelstate(DISABLE, ptr::null_mut()); }
        self.resume_state = DISABLE;
        let address = self.servers[server];
        let fd = match self.raw(41, [self.socket_family as i64, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0,0,0,0]) {
            Ok(fd) => fd as c_int,
            Err(_) => {
                unsafe { pthread_cancel::pthread_setcancelstate(self.entry_state, ptr::null_mut()); }
                self.resume_state = self.entry_state;
                return;
            }
        };
        self.descriptors.fds[slot].set(fd);
        self.pfd[slot] = PollFd { fd, events: POLLOUT, revents: 0 };
        let enabled: c_int = 1;
        let mut started = false;
        if self.raw(54, [fd as i64, 6, TCP_FASTOPEN_CONNECT, &enabled as *const c_int as i64,
            core::mem::size_of::<c_int>() as i64, 0]).is_ok() {
            let query_pointer = self.slots[slot].query;
            let query_length = self.slots[slot].query_length;
            let query = unsafe { core::slice::from_raw_parts(query_pointer, query_length) };
            let prefix = [(query.len() >> 8) as u8, query.len() as u8];
            let iovecs = [Iovec { base: prefix.as_ptr().cast_mut(), length: 2 },
                Iovec { base: query.as_ptr().cast_mut(), length: query.len() }];
            let mut message = Message::connected(&iovecs);
            message.name = address.bytes.as_ptr(); message.name_length = address.length;
            match self.raw(46, [fd as i64, &message as *const Message as i64, MSG_FASTOPEN|MSG_NOSIGNAL,0,0,0]) {
                Ok(length) => {
                    self.slots[slot].qpos = length;
                    if length == query_length + 2 { self.pfd[slot].events = POLLIN; }
                    started = true;
                }
                Err(error) if error == Errno::INPROGRESS => started = true,
                Err(_) => (),
            }
        }
        if !started {
            match self.raw(42, [fd as i64, address.bytes.as_ptr() as i64, address.length as i64,0,0,0]) {
                Ok(_) => started = true,
                Err(error) if error == Errno::INPROGRESS => started = true,
                Err(_) => (),
            }
        }
        if !started { self.descriptors.close(slot); self.pfd[slot].fd = -1; }
        unsafe { pthread_cancel::pthread_setcancelstate(self.entry_state, ptr::null_mut()); }
        self.resume_state = self.entry_state;
    }

    fn drain_udp(&mut self, servfail_retry: &mut usize) {
        while self.next < self.count {
            let temporary = self.next;
            let mut source = [0u8; 28];
            let source_length = self.servers[0].length;
            let length = self.slots[temporary].answer_length;
            let answer_pointer = self.slots[temporary].answer;
            let iovecs = [Iovec { base: answer_pointer, length }];
            let mut message = Message { name: source.as_mut_ptr(), name_length: source_length,
                iovecs: iovecs.as_ptr(), iovec_count: 1, control: ptr::null_mut(), control_length: 0, flags: 0 };
            // Unlike the strict core, input flags are zero.  The copied prefix
            // is bounded by the output buffer even when the kernel reports
            // MSG_TRUNC, and only then can selected C fall back to TCP.
            let received = unsafe { self.cp(47, [self.pfd[self.count].fd as i64,
                &mut message as *mut Message as i64, 0,0,0,0]) };
            let received = match received { Cp::Complete(length) => length, Cp::Failed(_) | Cp::Masked => break };
            if received < 4 || received > length { continue; }
            let Some(server) = self.source_server(&source, message.name_length) else { continue; };
            let answer = unsafe { core::slice::from_raw_parts(answer_pointer, received) };
            let mut target = None;
            for index in self.next..self.count {
                let candidate = &self.slots[index];
                if answer[0..2] == candidate.query_id.to_be_bytes() && candidate.state == SlotState::PendingUdp {
                    target = Some(index); break;
                }
            }
            let Some(target) = target else { continue; };
            let packet = answer;
            if !self.matching_reply(target, packet) { continue; }
            match packet[3] & 15 {
                0 | 3 => (),
                2 => {
                    if *servfail_retry != 0 { *servfail_retry -= 1; self.send_udp(target, server); }
                    continue;
                }
                _ => continue,
            }
            let truncated = packet[2] & 2 != 0 || message.flags & MSG_TRUNC != 0;
            if target != temporary { unsafe { ptr::copy_nonoverlapping(packet.as_ptr(), self.slots[target].answer, received); } }
            self.slots[target].state = SlotState::Accepted(received);
            if target == self.next {
                let states = core::array::from_fn(|index| self.slots[index].state);
                self.next = next_reusable(&states, self.count, self.next);
            }
            if self.next == self.count { self.pfd[self.count].events = 0; }
            if truncated {
                self.slots[target].state = SlotState::PendingTcp;
                self.start_tcp(target, server);
            }
        }
    }

    fn tcp_write(&mut self, slot: usize) -> bool {
        let query_pointer = self.slots[slot].query;
        let query_length = self.slots[slot].query_length;
        let query = unsafe { core::slice::from_raw_parts(query_pointer, query_length) };
        let position = self.slots[slot].qpos;
        let prefix = [(query.len() >> 8) as u8, query.len() as u8];
        let mut iovecs = [Iovec { base: ptr::null_mut(), length: 0 }; 2];
        let count = if position < 2 {
            iovecs[0] = Iovec { base: unsafe { prefix.as_ptr().add(position) }.cast_mut(), length: 2-position };
            iovecs[1] = Iovec { base: query.as_ptr().cast_mut(), length: query.len() };
            2
        } else {
            let query_position = position - 2;
            if query_position >= query.len() { return true; }
            iovecs[0] = Iovec { base: unsafe { query.as_ptr().add(query_position) }.cast_mut(), length: query.len()-query_position };
            1
        };
        let message = Message::connected(&iovecs[..count]);
        match unsafe { self.cp(46, [self.pfd[slot].fd as i64, &message as *const Message as i64, MSG_NOSIGNAL,0,0,0]) } {
            Cp::Complete(length) => {
                self.slots[slot].qpos += length;
                if self.slots[slot].qpos == query_length+2 { self.pfd[slot].events = POLLIN; }
                true
            }
            Cp::Failed(_) | Cp::Masked => false,
        }
    }

    fn tcp_read(&mut self, slot: usize) -> bool {
        let position = self.slots[slot].apos;
        let capacity = self.slots[slot].answer_length;
        let answer_pointer = self.slots[slot].answer;
        let answer = unsafe { core::slice::from_raw_parts_mut(answer_pointer, capacity) };
        let mut iovecs = [Iovec { base: ptr::null_mut(), length: 0 }; 2];
        let count = if position < 2 {
            iovecs[0] = Iovec { base: unsafe { self.slots[slot].frame_length.as_mut_ptr().add(position) }, length: 2-position };
            iovecs[1] = Iovec { base: answer.as_mut_ptr(), length: capacity };
            2
        } else {
            let answer_position = position-2;
            if answer_position >= capacity { return false; }
            iovecs[0] = Iovec { base: unsafe { answer.as_mut_ptr().add(answer_position) }, length: capacity-answer_position };
            1
        };
        let mut message = Message::connected(&iovecs[..count]);
        let received = match unsafe { self.cp(47, [self.pfd[slot].fd as i64, &mut message as *mut Message as i64, 0,0,0,0]) } {
            Cp::Complete(length) if length != 0 => length,
            Cp::Complete(_) | Cp::Failed(_) | Cp::Masked => return false,
        };
        self.slots[slot].apos += received;
        if self.slots[slot].apos < 2 { return true; }
        let declared = u16::from_be_bytes(self.slots[slot].frame_length) as usize;
        if declared < 13 || declared > capacity { return false; }
        if self.slots[slot].apos < declared + 2 { return true; }
        let packet = &answer[..declared];
        if !self.matching_reply(slot, packet) || !matches!(packet[3] & 15, 0 | 3) { return false; }
        self.slots[slot].state = SlotState::Accepted(declared);
        self.descriptors.close(slot); self.pfd[slot].fd = -1; self.pfd[slot].events = 0;
        true
    }

    fn run(&mut self) {
        let timeout = self.config.total_timeout_ms as u64;
        let attempts = self.config.attempts as u64;
        let interval = timeout / attempts;
        let mut servfail_retry = 0usize;
        let mut time = self.time_ms();
        let start = time;
        let mut previous = time.wrapping_sub(interval);
        while time.wrapping_sub(start) < timeout {
            if self.all_accepted() { break; }
            if time.wrapping_sub(previous) >= interval {
                for slot in 0..self.count {
                    if self.slots[slot].state == SlotState::PendingUdp {
                        for server in 0..self.server_count { self.send_udp(slot, server); }
                    }
                }
                previous = time;
                servfail_retry = 2*self.count;
            }
            let wait = previous.wrapping_add(interval).wrapping_sub(time).min(c_int::MAX as u64) as i64;
            let pollfds = self.pfd.as_mut_ptr();
            let polled = unsafe { self.cp(7, [pollfds as i64, (self.count+1) as i64, wait,0,0,0]) };
            let positive = matches!(polled, Cp::Complete(count) if count != 0);
            if !positive { time = self.time_ms(); continue; }
            let events: [i16; 3] = core::array::from_fn(|index| self.pfd[index].revents);
            // musl drains one UDP socket after every positive poll, even when
            // that socket did not report POLLIN and while an answer slot exists.
            self.drain_udp(&mut servfail_retry);
            for slot in 0..self.count {
                if events[slot] & POLLOUT != 0 && !self.tcp_write(slot) { return; }
            }
            for slot in 0..self.count {
                if events[slot] & POLLIN != 0 && !self.tcp_read(slot) { return; }
            }
            time = self.time_ms();
        }
    }
}

fn question_end(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *packet.get(offset)?;
        if length == 0 { return Some(offset + 1); }
        if length & 0xc0 == 0xc0 { return (offset + 1 < packet.len()).then_some(offset + 2); }
        if length & 0xc0 != 0 || length > 63 { return None; }
        offset = offset.checked_add(usize::from(length) + 1)?;
        if offset > packet.len() { return None; }
    }
}

fn slots(requests: BatchRequests<'_>) -> Result<([Slot; 2], usize), Errno> {
    let mut requests = match requests {
        BatchRequests::One(request) => [Some(request), None],
        BatchRequests::Two(first, second) => [Some(first), Some(second)],
    };
    let count = usize::from(requests[1].is_some()) + 1;
    let mut slots = [Slot { query: ptr::null(), query_length: 0, query_id: 0, answer: ptr::null_mut(),
        answer_length: 0, state: SlotState::PendingUdp, qpos: 0, apos: 0, frame_length: [0;2] }; 2];
    for (index, request) in requests[..count].iter_mut().enumerate() {
        let request = request.as_mut().unwrap();
        if request.query.len() < 12 || request.answer.len() < 12
            || u16::from_be_bytes([request.query[0], request.query[1]]) != request.query_id
            || question_end(request.query, 12).is_none_or(|end| end+4 > request.query.len()) { return Err(Errno::INVAL); }
        let start = request.answer.as_mut_ptr() as usize;
        let end = start.checked_add(request.answer.len()).ok_or(Errno::INVAL)?;
        if index != 0 && !common_answer_capacity(slots[0].answer_length, request.answer.len()) {
            // `__res_msend_rc` has one `asize`: its temporary receive buffer
            // can be copied to either source slot.  Reject unequal C buffers
            // before descriptors exist instead of widening the copy contract.
            return Err(Errno::INVAL);
        }
        for prior in &slots[..index] {
            let other_start = prior.answer as usize;
            let other_end = other_start + prior.answer_length;
            if start < other_end && other_start < end { return Err(Errno::INVAL); }
        }
        slots[index] = Slot { query: request.query.as_ptr(), query_length: request.query.len(), query_id: request.query_id,
            answer: request.answer.as_mut_ptr(), answer_length: request.answer.len(), state: SlotState::PendingUdp,
            qpos: 0, apos: 0, frame_length: [0;2] };
    }
    Ok((slots, count))
}

fn addresses(config: &CResolverBatchConfig) -> Result<([SocketAddress;3],usize,c_int), Errno> {
    if config.nameserver_count == 0 || config.nameserver_count > 3 || config.total_timeout_ms == 0 || config.attempts == 0 { return Err(Errno::INVAL); }
    let mut addresses = [SocketAddress { bytes: [0;28], length: 0, family: AF_INET };3];
    let mut family = AF_INET;
    for index in 0..config.nameserver_count {
        let address = SocketAddress::from_server(config.nameservers[index]).ok_or(Errno::AFNOSUPPORT)?;
        if address.family == AF_INET6 { family = AF_INET6; }
        addresses[index] = address;
    }
    if family == AF_INET6 {
        for address in &mut addresses[..config.nameserver_count] { *address = address.mapped_v4(); }
    }
    Ok((addresses, config.nameserver_count, family))
}

/// Execute one or two selected C resolver requests in one source-shaped batch.
/// # Safety
/// The current thread has initialized owned cancellation state. Request ranges
/// remain valid to normal return or cancellation cleanup and answers are
/// disjoint mutable ranges.
pub(super) unsafe fn exchange(config: &CResolverBatchConfig, requests: BatchRequests<'_>) -> BatchOutcome {
    let (slots, count) = match slots(requests) { Ok(value) => value, Err(error) => return BatchOutcome { result: Err(ExchangeError::Setup(error)), last_errno: None, masked_errno: None } };
    let (mut servers, server_count, mut family) = match addresses(config) { Ok(value) => value, Err(error) => return BatchOutcome { result: Err(ExchangeError::Setup(error)), last_errno: None, masked_errno: None } };
    let mut entry_state = DISABLE;
    unsafe { pthread_cancel::pthread_setcancelstate(DISABLE, &mut entry_state); }
    let descriptors = core::pin::pin!(CleanupDescriptors::new());
    let descriptors = descriptors.as_ref().get_ref();
    let mut open = |family: c_int| unsafe { raw_syscall::syscall3(41, family as i64, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0) };
    let mut fd = open(family);
    if fd < 0 && family == AF_INET6 && fd == -(Errno::AFNOSUPPORT.raw() as i64) {
        let Some(first_v4) = config.nameservers[..server_count].iter().position(|server| server.family as c_int == AF_INET) else {
            unsafe { pthread_cancel::pthread_setcancelstate(entry_state, ptr::null_mut()); }
            return BatchOutcome { result: Err(ExchangeError::Setup(Errno::AFNOSUPPORT)), last_errno: None, masked_errno: None };
        };
        family = AF_INET;
        for index in 0..server_count { servers[index] = SocketAddress::from_server(config.nameservers[index]).unwrap(); }
        let _ = first_v4;
        fd = open(family);
    }
    if fd < 0 {
        let error = Errno::from_raw((-fd) as c_int).unwrap_or(Errno::IO);
        unsafe { pthread_cancel::pthread_setcancelstate(entry_state, ptr::null_mut()); }
        return BatchOutcome { result: Err(ExchangeError::Setup(error)), last_errno: None, masked_errno: None };
    }
    if family == AF_INET6 {
        let disabled: c_int = 0;
        let _ = unsafe { raw_syscall::syscall5(54, fd, 41, IPV6_V6ONLY, &disabled as *const c_int as i64, core::mem::size_of::<c_int>() as i64) };
    }
    let mut bound = [0u8;28]; bound[..2].copy_from_slice(&(family as u16).to_ne_bytes());
    let bound_length = if family == AF_INET6 { 28 } else { 16 };
    let bound_result = unsafe { raw_syscall::syscall3(49, fd, bound.as_ptr() as i64, bound_length) };
    if bound_result < 0 {
        unsafe { raw_syscall::syscall1(3, fd); pthread_cancel::pthread_setcancelstate(entry_state, ptr::null_mut()); }
        let error = Errno::from_raw((-bound_result) as c_int).unwrap_or(Errno::IO);
        return BatchOutcome { result: Err(ExchangeError::Setup(error)), last_errno: None, masked_errno: None };
    }
    descriptors.fds[2].set(fd as c_int);
    let mut node = core::pin::pin!(MaybeUninit::<pthread_cancel::CleanupNode>::uninit());
    let node_pointer = node.as_mut().get_mut().as_mut_ptr();
    unsafe { pthread_cancel::_pthread_cleanup_push(node_pointer, Some(cleanup), (descriptors as *const CleanupDescriptors).cast_mut().cast()); }
    let mut pfd = [PollFd { fd: -1, events: 0, revents: 0 };3];
    pfd[count] = PollFd { fd: fd as c_int, events: POLLIN, revents: 0 };
    unsafe { pthread_cancel::pthread_setcancelstate(entry_state, ptr::null_mut()); }
    let mut batch = Batch { slots, count, servers, server_count, socket_family: family, config, descriptors,
        entry_state, resume_state: entry_state, consumed_masked: false, last_errno: None, pfd, next: 0 };
    batch.run();
    let lengths = batch.lengths();
    let last_errno = batch.last_errno.map(Errno::raw);
    let masked_errno = if batch.consumed_masked { last_errno } else { None };
    let resume_state = batch.resume_state;
    // `start_tcp` deliberately restored entry state, so normal completion can
    // reach this point enabled.  Retirement is a source cleanup transaction:
    // disable only around the cleanup callback, then restore the saved actual
    // post-CP state rather than that temporary disabled value.
    unsafe { pthread_cancel::pthread_setcancelstate(DISABLE, ptr::null_mut());
        pthread_cancel::_pthread_cleanup_pop(node_pointer, 1);
        pthread_cancel::pthread_setcancelstate(resume_state, ptr::null_mut()); }
    BatchOutcome { result: Ok(BatchReceipt { lengths, count }), last_errno, masked_errno }
}
