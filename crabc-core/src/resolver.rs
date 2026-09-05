//! Stateless Linux LP64 resolver transport operations.

use crate::{net, Result};

/// IPv4 address family in the Linux socket ABI.
pub const AF_INET: u16 = 2;
/// IPv6 address family in the Linux socket ABI.
pub const AF_INET6: u16 = 10;
/// UDP socket type in the Linux socket ABI.
pub const SOCK_DGRAM: u32 = 2;
/// Stream socket type in the Linux socket ABI.
pub const SOCK_STREAM: u32 = 1;
/// Nonblocking socket creation flag in the Linux socket ABI.
const SOCK_NONBLOCK: u32 = 0x0000_0800;
/// Close-on-exec socket flag.
pub const SOCK_CLOEXEC: u32 = 0x0008_0000;
/// `MSG_NOSIGNAL`, used for the datagram send operation.
pub const MSG_NOSIGNAL: u32 = 0x4000;
/// `MSG_TRUNC`, used to learn whether a bounded datagram buffer lost data.
const MSG_TRUNC: u32 = 0x20;
/// DNS Internet class.
pub const CLASS_IN: u16 = 1;
/// DNS address record.
pub const TYPE_A: u16 = 1;
/// DNS canonical-name record.
pub const TYPE_CNAME: u16 = 5;
/// DNS pointer record.
pub const TYPE_PTR: u16 = 12;
/// DNS IPv6 address record.
pub const TYPE_AAAA: u16 = 28;
/// Maximum DNS wire name size, including its root terminator.
pub const MAX_NAME_WIRE: usize = 256;
/// Maximum nameservers accepted by the musl resolver configuration.
pub const MAX_NAMESERVERS: usize = 3;

/// A caller-owned nameserver endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NameServer {
    /// Linux address-family value.
    pub family: u16,
    /// Network-order address bytes in the first four or sixteen bytes.
    pub address: [u8; 16],
    /// UDP port in host byte order. Zero selects DNS port 53.
    pub port: u16,
    /// IPv6 scope identifier, ignored for IPv4.
    pub scope_id: u32,
}

impl NameServer {
    /// Builds an IPv4 nameserver using DNS port 53.
    #[inline]
    pub const fn ipv4(address: [u8; 4]) -> Self {
        let mut bytes = [0; 16];
        bytes[0] = address[0];
        bytes[1] = address[1];
        bytes[2] = address[2];
        bytes[3] = address[3];
        Self {
            family: AF_INET,
            address: bytes,
            port: 53,
            scope_id: 0,
        }
    }

    /// Builds an IPv6 nameserver using DNS port 53.
    #[inline]
    pub const fn ipv6(address: [u8; 16], scope_id: u32) -> Self {
        Self {
            family: AF_INET6,
            address,
            port: 53,
            scope_id,
        }
    }
}

/// Bounded DNS exchange configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExchangeConfig {
    /// Nameservers, in configured order.
    pub nameservers: [NameServer; MAX_NAMESERVERS],
    /// Number of initialized entries in [`Self::nameservers`].
    pub nameserver_count: usize,
    /// Per-server receive timeout in milliseconds.
    pub timeout_ms: u32,
    /// Number of configured-order attempts.
    pub attempts: u8,
}

impl ExchangeConfig {
    /// Constructs a one-server configuration with a bounded timeout.
    #[inline]
    pub const fn single(nameserver: NameServer, timeout_ms: u32) -> Self {
        Self {
            nameservers: [nameserver; MAX_NAMESERVERS],
            nameserver_count: 1,
            timeout_ms,
            attempts: 1,
        }
    }
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: u16,
    address: u32,
    zero: [u8; 8],
}

#[repr(C)]
struct SockaddrIn6 {
    family: u16,
    port: u16,
    flow_info: u32,
    address: [u8; 16],
    scope_id: u32,
}

const _: () = assert!(core::mem::size_of::<PollFd>() == 8);
const _: () = assert!(core::mem::align_of::<PollFd>() == 4);
const _: () = assert!(core::mem::offset_of!(PollFd, fd) == 0);
const _: () = assert!(core::mem::offset_of!(PollFd, events) == 4);
const _: () = assert!(core::mem::offset_of!(PollFd, revents) == 6);
const _: () = assert!(core::mem::size_of::<Timespec>() == 16);
const _: () = assert!(core::mem::align_of::<Timespec>() == 8);
const _: () = assert!(core::mem::offset_of!(Timespec, seconds) == 0);
const _: () = assert!(core::mem::offset_of!(Timespec, nanoseconds) == 8);
const _: () = assert!(core::mem::size_of::<SockaddrIn>() == 16);
const _: () = assert!(core::mem::align_of::<SockaddrIn>() == 4);
const _: () = assert!(core::mem::offset_of!(SockaddrIn, family) == 0);
const _: () = assert!(core::mem::offset_of!(SockaddrIn, port) == 2);
const _: () = assert!(core::mem::offset_of!(SockaddrIn, address) == 4);
const _: () = assert!(core::mem::offset_of!(SockaddrIn, zero) == 8);
const _: () = assert!(core::mem::size_of::<SockaddrIn6>() == 28);
const _: () = assert!(core::mem::align_of::<SockaddrIn6>() == 4);
const _: () = assert!(core::mem::offset_of!(SockaddrIn6, family) == 0);
const _: () = assert!(core::mem::offset_of!(SockaddrIn6, port) == 2);
const _: () = assert!(core::mem::offset_of!(SockaddrIn6, flow_info) == 4);
const _: () = assert!(core::mem::offset_of!(SockaddrIn6, address) == 8);
const _: () = assert!(core::mem::offset_of!(SockaddrIn6, scope_id) == 24);

const POLLIN: i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;
const CLOCK_MONOTONIC: i32 = 1;

enum UdpResponse {
    Complete(usize),
    Truncated,
}

/// Initialized destination for a DNS transport operation. The byte view is
/// exactly one Linux sockaddr record; callers cannot construct invalid values.
pub struct DnsSocketAddress {
    family: i32,
    storage: [u8; 28],
    length: u32,
}

impl DnsSocketAddress {
    /// Linux address family of the initialized record.
    pub fn family(&self) -> i32 { self.family }
    /// Borrow the initialized Linux sockaddr bytes for this destination.
    pub fn as_bytes(&self) -> &[u8] { &self.storage[..self.length as usize] }
}

/// DNS socket lifetime selected by the shared exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsSocketKind { Datagram, Stream }

/// Readiness needed by a bounded DNS operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsWait { Readable, Writable }

/// The actual result of a DNS cancellation-point operation. MASKED
/// cancellation is distinct from an ordinary syscall returning ECANCELED:
/// its source semantics depend on whether this was UDP, TCP, or a wait.
pub enum DnsIoResult<T> {
    /// The syscall completed with this result.
    Complete(T),
    /// The syscall failed without consuming MASKED cancellation.
    Failed(crate::Errno),
    /// The C owner consumed MASKED cancellation and changed state to DISABLE.
    MaskedCancellation,
}

impl<T> From<Result<T>> for DnsIoResult<T> {
    fn from(result: Result<T>) -> Self {
        match result { Ok(value) => Self::Complete(value), Err(error) => Self::Failed(error) }
    }
}

/// One UDP receive result, including the kernel's truncation observation.
pub struct DnsDatagram {
    /// Full byte count reported by the receive operation.
    pub length: usize,
    /// Whether the bounded receive lost a packet suffix.
    pub truncated: bool,
}

/// Progress made while opening the TCP connection for a DNS query.
pub enum DnsTcpStart {
    /// Native connect completed; the ordinary immediate frame send may begin.
    Connected,
    /// Source TCP-start queued this many bytes, including the two-byte length.
    /// If the frame is incomplete, wait for writable before sending its suffix.
    Queued { frame_bytes: usize },
}

/// Continuation after a TCP socket or initial connection could not be opened.
pub enum DnsTcpFailure {
    /// Preserve the native transport's immediate failed-attempt result.
    Immediate,
    /// The owned C source reenters its real cancellation-point poll until the
    /// current query deadline, with no active descriptor events.
    WaitUntilDeadline,
}

/// DNS-only syscall and descriptor-lifetime boundary. The native implementation
/// uses raw Linux operations. An owned C implementation may execute the actual
/// I/O through its cancellation window and explicitly register descriptor
/// cleanup. The shared engine retains DNS framing, deadlines, and retries.
///
/// Calls are serial. Each successful socket acquisition is reported before
/// any operation can cancel; `close_socket` retires it before another socket
/// is acquired. At most one descriptor is live. Callback byte counts are
/// checked before they can advance offsets or select a slice.
pub trait DnsTransport {
    /// Register a newly acquired descriptor before any cancellation point.
    fn socket_opened(&mut self, fd: i32, kind: DnsSocketKind);
    /// Close and retire the registered descriptor without a cancellation point.
    fn close_socket(&mut self, fd: i32);
    /// Observe a raw socket creation, UDP connect, or monotonic-clock failure.
    /// These DNS operations remain outside the I/O CP methods, but a C owner
    /// still needs their actual errno after earlier MASKED cancellation.
    fn syscall_failed(&mut self, _error: crate::Errno) {}
    /// Enter the disabled TCP-start phase before socket acquisition. C source
    /// restores its original entry state after this phase even when acquisition
    /// fails; native transport has no cancellation state and returns immediately.
    fn stream_starting(&mut self) -> DnsTcpFailure { DnsTcpFailure::Immediate }
    /// Execute one readiness wait with this remaining millisecond timeout.
    fn wait(&mut self, fd: i32, event: DnsWait, timeout_ms: u32) -> DnsIoResult<bool>;
    /// Send one datagram or a stream prefix on an already connected socket.
    fn send(&mut self, fd: i32, bytes: &[u8], kind: DnsSocketKind) -> DnsIoResult<usize>;
    /// Receive stream bytes into the provided writable range.
    fn receive_stream(&mut self, fd: i32, bytes: &mut [u8]) -> DnsIoResult<usize>;
    /// Receive one datagram into the provided writable range.
    fn receive_datagram(&mut self, fd: i32, bytes: &mut [u8]) -> DnsIoResult<DnsDatagram>;
    /// Start TCP with cancellation disabled in an owned C implementation.
    /// Its source-mapped fast-open send may queue part or all of the frame.
    /// The native implementation retains its existing raw connect/wait path.
    fn start_tcp(&mut self, fd: i32, target: &DnsSocketAddress, query: &[u8], deadline_ms: i64)
        -> Result<DnsTcpStart>;
}

struct RawDnsTransport;

#[inline]
fn invalid() -> crate::Errno {
    crate::Errno::INVAL
}

#[inline]
fn malformed() -> crate::Errno {
    crate::Errno::BADMSG
}

#[inline]
fn write_wire_name(name: &[u8], output: &mut [u8]) -> Result<usize> {
    if name.is_empty() || output.is_empty() {
        return Err(invalid());
    }
    let mut written = 0usize;
    let mut label_start = 0usize;
    let mut index = 0usize;
    while index <= name.len() {
        let at_end = index == name.len();
        if !at_end && name[index] != b'.' {
            index += 1;
            continue;
        }
        let label_length = index.saturating_sub(label_start);
        if label_length == 0 {
            if !(at_end && index != 0 && name[index - 1] == b'.') {
                return Err(invalid());
            }
        } else if label_length > 63 || written.checked_add(label_length + 2).is_none() {
            return Err(invalid());
        } else {
            if written + label_length + 1 >= output.len() {
                return Err(crate::Errno::NAMETOOLONG);
            }
            output[written] = label_length as u8;
            output[written + 1..written + 1 + label_length]
                .copy_from_slice(&name[label_start..index]);
            written += label_length + 1;
        }
        if at_end {
            break;
        }
        label_start = index + 1;
        index += 1;
    }
    if written >= output.len() {
        return Err(crate::Errno::NAMETOOLONG);
    }
    output[written] = 0;
    Ok(written + 1)
}

/// Encodes one recursive DNS A/AAAA/PTR query into caller storage.
pub fn encode_query(
    name: &[u8],
    record_type: u16,
    query_id: u16,
    output: &mut [u8],
) -> Result<usize> {
    if output.len() < 12 {
        return Err(crate::Errno::MSGSIZE);
    }
    let mut wire_name = [0u8; MAX_NAME_WIRE];
    let name_length = write_wire_name(name, &mut wire_name)?;
    let total = 12usize
        .checked_add(name_length)
        .and_then(|value| value.checked_add(4))
        .ok_or(crate::Errno::MSGSIZE)?;
    if total > output.len() {
        return Err(crate::Errno::MSGSIZE);
    }
    output[..total].fill(0);
    output[0] = (query_id >> 8) as u8;
    output[1] = query_id as u8;
    output[2] = 0x01;
    output[5] = 0x01;
    output[12..12 + name_length].copy_from_slice(&wire_name[..name_length]);
    let qtype = 12 + name_length;
    output[qtype] = (record_type >> 8) as u8;
    output[qtype + 1] = record_type as u8;
    output[qtype + 2] = 0;
    output[qtype + 3] = CLASS_IN as u8;
    Ok(total)
}

/// A validated DNS response borrowing its caller-owned packet buffer.
pub struct DnsResponse<'packet> {
    packet: &'packet [u8],
    answer_offset: usize,
    answer_count: u16,
    response_code: u8,
    truncated: bool,
}

impl<'packet> DnsResponse<'packet> {
    /// Validates transaction, question, and DNS header fields.
    pub fn parse(
        packet: &'packet [u8],
        query_name: &[u8],
        record_type: u16,
        query_id: u16,
    ) -> Result<Self> {
        if packet.len() < 12 {
            return Err(malformed());
        }
        let id = u16::from_be_bytes([packet[0], packet[1]]);
        if id != query_id || packet[2] & 0x80 == 0 || packet[2] & 0x78 != 0 {
            return Err(malformed());
        }
        if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
            return Err(malformed());
        }
        let mut expected_name = [0u8; MAX_NAME_WIRE];
        let expected_length = write_wire_name(query_name, &mut expected_name)?;
        let question_end = skip_name(packet, 12)?;
        if question_end + 4 > packet.len()
            || question_end - 12 != expected_length
            || packet[12..question_end] != expected_name[..expected_length]
            || u16::from_be_bytes([packet[question_end], packet[question_end + 1]])
                != record_type
            || u16::from_be_bytes([packet[question_end + 2], packet[question_end + 3]])
                != CLASS_IN
        {
            return Err(malformed());
        }
        Ok(Self {
            packet,
            answer_offset: question_end + 4,
            answer_count: u16::from_be_bytes([packet[6], packet[7]]),
            response_code: packet[3] & 0x0f,
            truncated: packet[2] & 0x02 != 0,
        })
    }

    /// Returns the DNS response code from the validated header.
    #[inline]
    pub const fn response_code(&self) -> u8 {
        self.response_code
    }

    /// Returns whether the server marked this UDP response truncated.
    #[inline]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Copies the selected answer's raw RDATA or expanded DNS name.
    pub fn rdata_at(
        &self,
        record_type: u16,
        ordinal: usize,
        output: &mut [u8],
    ) -> Result<Option<usize>> {
        let mut offset = self.answer_offset;
        let mut found = 0usize;
        let mut index = 0u16;
        while index < self.answer_count {
            let name_end = skip_name(self.packet, offset)?;
            if name_end + 10 > self.packet.len() {
                return Err(malformed());
            }
            let kind = u16::from_be_bytes([self.packet[name_end], self.packet[name_end + 1]]);
            let class =
                u16::from_be_bytes([self.packet[name_end + 2], self.packet[name_end + 3]]);
            let length =
                u16::from_be_bytes([self.packet[name_end + 8], self.packet[name_end + 9]])
                    as usize;
            let data = name_end + 10;
            if data
                .checked_add(length)
                .filter(|end| *end <= self.packet.len())
                .is_none()
            {
                return Err(malformed());
            }
            if kind == record_type && class == CLASS_IN {
                if found == ordinal {
                    if record_type == TYPE_CNAME || record_type == TYPE_PTR {
                        let length = expand_name(self.packet, data, output)?;
                        return Ok(Some(length));
                    }
                    if length > output.len() {
                        return Err(crate::Errno::MSGSIZE);
                    }
                    output[..length].copy_from_slice(&self.packet[data..data + length]);
                    return Ok(Some(length));
                }
                found += 1;
            }
            offset = data + length;
            index += 1;
        }
        Ok(None)
    }
}

/// Validates a DNS compression pointer and returns its prior target.
///
/// RFC 1035 compression points to an earlier domain-name occurrence in the
/// message body. Checking that invariant prevents a framing-only parser from
/// accepting a header byte, dangling, forward, or cyclic pointer without
/// expanding it.
fn compression_target(packet: &[u8], offset: usize) -> Result<usize> {
    let next = offset.checked_add(1).ok_or_else(malformed)?;
    if next >= packet.len() {
        return Err(malformed());
    }
    let target = ((packet[offset] as usize & 0x3f) << 8) | packet[next] as usize;
    if target < 12 || target >= offset {
        return Err(malformed());
    }
    Ok(target)
}

fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize> {
    let mut encoded_end = None;
    let mut steps = 0usize;
    loop {
        if offset >= packet.len() {
            return Err(malformed());
        }
        let length = packet[offset];
        if length & 0xc0 == 0xc0 {
            let target = compression_target(packet, offset)?;
            if encoded_end.is_none() {
                encoded_end = Some(offset.checked_add(2).ok_or_else(malformed)?);
            }
            offset = target;
            steps += 1;
            if steps > 128 {
                return Err(malformed());
            }
            continue;
        }
        if length > 63 {
            return Err(malformed());
        }
        offset = offset.checked_add(1).ok_or_else(malformed)?;
        if length == 0 {
            return Ok(encoded_end.unwrap_or(offset));
        }
        if offset + length as usize > packet.len() {
            return Err(malformed());
        }
        offset += length as usize;
        steps += 1;
        if steps > 128 {
            return Err(malformed());
        }
    }
}

fn expand_name(packet: &[u8], start: usize, output: &mut [u8]) -> Result<usize> {
    let mut offset = start;
    let mut written = 0usize;
    let mut consumed = 0usize;
    let mut jumped = false;
    let mut jumps = 0usize;
    loop {
        if offset >= packet.len() {
            return Err(malformed());
        }
        let length = packet[offset];
        if length & 0xc0 == 0xc0 {
            let target = compression_target(packet, offset)?;
            if !jumped {
                consumed += 2;
            }
            offset = target;
            jumped = true;
            jumps += 1;
            if jumps > 128 {
                return Err(malformed());
            }
            continue;
        }
        if length > 63 {
            return Err(malformed());
        }
        offset += 1;
        if length == 0 {
            if written == 0 {
                if output.is_empty() {
                    return Err(crate::Errno::MSGSIZE);
                }
                output[0] = b'.';
                return Ok(1);
            }
            let _ = consumed;
            return Ok(written);
        }
        let length = length as usize;
        if offset + length > packet.len() {
            return Err(malformed());
        }
        if written != 0 {
            if written + 1 >= output.len() {
                return Err(crate::Errno::MSGSIZE);
            }
            output[written] = b'.';
            written += 1;
        }
        if written + length >= output.len() {
            return Err(crate::Errno::MSGSIZE);
        }
        output[written..written + length].copy_from_slice(&packet[offset..offset + length]);
        written += length;
        offset += length;
        if !jumped {
            consumed += length + 1;
        }
    }
}

fn server_address(server: NameServer) -> Result<DnsSocketAddress> {
    let mut result = DnsSocketAddress {
        family: server.family as i32,
        storage: [0; 28],
        length: 0,
    };
    match server.family {
        AF_INET => {
            let address = SockaddrIn {
                family: AF_INET,
                port: (if server.port == 0 { 53 } else { server.port }).to_be(),
                address: u32::from_ne_bytes([
                    server.address[0],
                    server.address[1],
                    server.address[2],
                    server.address[3],
                ]),
                zero: [0; 8],
            };
            // SAFETY: `address` is a live, initialized C-layout record and
            // the source slice covers exactly its private Linux ABI size.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&address as *const SockaddrIn).cast::<u8>(),
                    core::mem::size_of::<SockaddrIn>(),
                )
            };
            result.storage[..bytes.len()].copy_from_slice(bytes);
            result.length = bytes.len() as u32;
        }
        AF_INET6 => {
            let address = SockaddrIn6 {
                family: AF_INET6,
                port: (if server.port == 0 { 53 } else { server.port }).to_be(),
                flow_info: 0,
                address: server.address,
                scope_id: server.scope_id,
            };
            // SAFETY: `address` is a live, initialized C-layout record and
            // the source slice covers exactly its private Linux ABI size.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&address as *const SockaddrIn6).cast::<u8>(),
                    core::mem::size_of::<SockaddrIn6>(),
                )
            };
            result.storage[..bytes.len()].copy_from_slice(bytes);
            result.length = bytes.len() as u32;
        }
        _ => return Err(invalid()),
    }
    Ok(result)
}

fn monotonic_millis(transport: &mut impl DnsTransport) -> Result<i64> {
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: `value` is the exact two-word admitted Linux LP64 timespec output
    // record and remains live for the direct syscall.
    if let Err(error) = unsafe {
        crate::time::clock_gettime_raw(CLOCK_MONOTONIC, (&mut value as *mut Timespec).cast())
    } {
        transport.syscall_failed(error);
        return Err(error);
    }
    Ok(value
        .seconds
        .saturating_mul(1_000)
        .saturating_add(value.nanoseconds / 1_000_000))
}

fn deadline_after(timeout_ms: u32, transport: &mut impl DnsTransport) -> Result<i64> {
    Ok(monotonic_millis(transport)?.saturating_add(timeout_ms as i64))
}

fn remaining_millis(deadline: i64, transport: &mut impl DnsTransport) -> Result<u32> {
    let now = monotonic_millis(transport)?;
    if now >= deadline {
        return Ok(0);
    }
    Ok((deadline - now).min(u32::MAX as i64) as u32)
}

impl DnsTransport for RawDnsTransport {
    fn socket_opened(&mut self, _fd: i32, _kind: DnsSocketKind) {}
    fn close_socket(&mut self, fd: i32) { let _ = crate::io::close(fd); }

    fn wait(&mut self, fd: i32, event: DnsWait, remaining: u32) -> DnsIoResult<bool> {
        let events = match event { DnsWait::Readable => POLLIN, DnsWait::Writable => POLLOUT };
        let mut poll = PollFd { fd, events, revents: 0 };
        let timeout = Timespec {
            seconds: (remaining / 1_000) as i64,
            nanoseconds: ((remaining % 1_000) as i64) * 1_000_000,
        };
        // SAFETY: `poll` and `timeout` are valid local Linux ABI records.
        let result = unsafe {
            crate::event::ppoll_raw(
                (&mut poll as *mut PollFd).cast(), 1,
                (&timeout as *const Timespec).cast(), core::ptr::null(), 8,
            )
        };
        result.map(|count| count != 0 && poll.revents & (events | POLLERR | POLLHUP | POLLNVAL) != 0).into()
    }

    fn send(&mut self, fd: i32, bytes: &[u8], _kind: DnsSocketKind) -> DnsIoResult<usize> {
        // SAFETY: the borrowed slice remains readable through the syscall.
        // A connected stream uses sendto with a null destination as before.
        unsafe { net::sendto_raw(fd, bytes.as_ptr(), bytes.len(), MSG_NOSIGNAL, core::ptr::null(), 0) }.into()
    }

    fn receive_stream(&mut self, fd: i32, bytes: &mut [u8]) -> DnsIoResult<usize> {
        // SAFETY: the borrowed slice remains exclusively writable through the
        // syscall; no source-address output is requested.
        unsafe { net::recvfrom_raw(fd, bytes.as_mut_ptr(), bytes.len(), 0, core::ptr::null_mut(), core::ptr::null_mut()) }.into()
    }

    fn receive_datagram(&mut self, fd: i32, bytes: &mut [u8]) -> DnsIoResult<DnsDatagram> {
        let iovec = crate::io::Iovec { iov_base: bytes.as_mut_ptr(), iov_len: bytes.len() };
        // SAFETY: the iovec covers exactly the exclusive borrowed range.
        // MSG_TRUNC retains the existing full-datagram-length observation.
        unsafe { net::recvmsg_raw(fd, &iovec, 1, MSG_TRUNC) }
            .map(|(length, flags)| DnsDatagram { length, truncated: flags & MSG_TRUNC != 0 }).into()
    }

    fn start_tcp(&mut self, fd: i32, target: &DnsSocketAddress, _query: &[u8], deadline: i64) -> Result<DnsTcpStart> {
        // SAFETY: the destination is an initialized Linux sockaddr record.
        match unsafe { net::connect_raw(fd, target.storage.as_ptr(), target.length) } {
            Ok(()) => {}
            Err(error) if error == crate::Errno::INPROGRESS || error == crate::Errno::ALREADY => {
                if !poll_until(fd, DnsWait::Writable, deadline, self)? { return Err(crate::Errno::TIMEDOUT); }
                let pending = net::socket_error(fd)?;
                if pending != 0 { return Err(crate::Errno::from_raw(pending).unwrap_or(crate::Errno::IO)); }
            }
            Err(error) => return Err(error),
        }
        Ok(DnsTcpStart::Connected)
    }
}

fn poll_until(fd: i32, event: DnsWait, deadline: i64, transport: &mut impl DnsTransport) -> Result<bool> {
    loop {
        let remaining = remaining_millis(deadline, transport)?;
        if remaining == 0 { return Ok(false); }
        match transport.wait(fd, event, remaining) {
            DnsIoResult::Complete(ready) => return Ok(ready),
            DnsIoResult::Failed(error) if error == crate::Errno::INTR => continue,
            // musl res_msend retries its outer loop after poll returns a
            // nonpositive result, including consumed MASKED cancellation.
            DnsIoResult::MaskedCancellation => continue,
            DnsIoResult::Failed(error) => return Err(error),
        }
    }
}

fn send_all(fd: i32, bytes: &[u8], deadline: i64, transport: &mut impl DnsTransport) -> Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if remaining_millis(deadline, transport)? == 0 { return Err(crate::Errno::TIMEDOUT); }
        match transport.send(fd, &bytes[offset..], DnsSocketKind::Stream) {
            DnsIoResult::Complete(0) => return Err(crate::Errno::PIPE),
            DnsIoResult::Complete(length) if length <= bytes.len() - offset => offset += length,
            DnsIoResult::Complete(_) => return Err(crate::Errno::OVERFLOW),
            DnsIoResult::Failed(error) if error == crate::Errno::INTR => continue,
            DnsIoResult::Failed(error) if error == crate::Errno::AGAIN || error == crate::Errno::WOULDBLOCK => {
                if !poll_until(fd, DnsWait::Writable, deadline, transport)? { return Err(crate::Errno::TIMEDOUT); }
            }
            // Unlike UDP send, source TCP send failure retires the attempt.
            DnsIoResult::MaskedCancellation => return Err(crate::Errno::CANCELED),
            DnsIoResult::Failed(error) => return Err(error),
        }
    }
    Ok(())
}

fn send_datagram(fd: i32, bytes: &[u8], deadline: i64, transport: &mut impl DnsTransport) -> Result<()> {
    loop {
        if remaining_millis(deadline, transport)? == 0 { return Err(crate::Errno::TIMEDOUT); }
        match transport.send(fd, bytes, DnsSocketKind::Datagram) {
            DnsIoResult::Complete(length) if length == bytes.len() => return Ok(()),
            // A query is one datagram. A short successful send must never
            // become a second datagram containing only its unsent suffix.
            DnsIoResult::Complete(_) => return Err(crate::Errno::MSGSIZE),
            // res_msend ignores a canceled UDP send and proceeds to its
            // response wait. This is not a fabricated successful byte count.
            DnsIoResult::MaskedCancellation => return Ok(()),
            DnsIoResult::Failed(error) if error == crate::Errno::INTR => continue,
            DnsIoResult::Failed(error) if error == crate::Errno::AGAIN || error == crate::Errno::WOULDBLOCK => {
                if !poll_until(fd, DnsWait::Writable, deadline, transport)? { return Err(crate::Errno::TIMEDOUT); }
            }
            DnsIoResult::Failed(error) => return Err(error),
        }
    }
}

fn receive_exact(fd: i32, bytes: &mut [u8], deadline: i64, transport: &mut impl DnsTransport) -> Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if !poll_until(fd, DnsWait::Readable, deadline, transport)? { return Err(crate::Errno::TIMEDOUT); }
        let remaining = bytes.len() - offset;
        match transport.receive_stream(fd, &mut bytes[offset..]) {
            DnsIoResult::Complete(0) => return Err(crate::Errno::CONNRESET),
            DnsIoResult::Complete(length) if length <= remaining => offset += length,
            DnsIoResult::Complete(_) => return Err(crate::Errno::OVERFLOW),
            DnsIoResult::Failed(error) if error == crate::Errno::INTR || error == crate::Errno::AGAIN || error == crate::Errno::WOULDBLOCK => continue,
            DnsIoResult::MaskedCancellation => return Err(crate::Errno::CANCELED),
            DnsIoResult::Failed(error) => return Err(error),
        }
    }
    Ok(())
}

/// Receives one connected UDP datagram without accepting a partial prefix.
fn receive_datagram(fd: i32, bytes: &mut [u8], transport: &mut impl DnsTransport) -> Result<usize> {
    match transport.receive_datagram(fd, bytes) {
        DnsIoResult::Complete(packet) if packet.length <= bytes.len() && !packet.truncated => Ok(packet.length),
        DnsIoResult::Complete(_) => Err(crate::Errno::OVERFLOW),
        // res_msend leaves its inner UDP receive loop on this result, then
        // polls again with the same socket and remaining deadline.
        DnsIoResult::MaskedCancellation => Err(crate::Errno::AGAIN),
        DnsIoResult::Failed(error) => Err(error),
    }
}

/// Returns the byte after the one DNS question required by this transport.
fn one_question_end(packet: &[u8]) -> Result<usize> {
    if packet.len() < 12 || u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return Err(malformed());
    }
    let name_end = skip_name(packet, 12)?;
    let question_end = name_end.checked_add(4).ok_or_else(malformed)?;
    if question_end > packet.len() {
        return Err(malformed());
    }
    Ok(question_end)
}

/// Checks the response header and the exact echoed DNS question.
///
/// DNS servers may add or omit resource records relative to the query, so the
/// question is the bounded correlation seam. `exchange` prevalidates `query`,
/// leaving a malformed received packet as an ordinary ignored datagram.
fn matching_question_end(packet: &[u8], query: &[u8], query_id: u16) -> Option<usize> {
    if packet.len() < 12
        || u16::from_be_bytes([packet[0], packet[1]]) != query_id
        || packet[2] & 0x80 == 0
        || packet[2] & 0x78 != 0
    {
        return None;
    }
    let query_end = one_question_end(query).ok()?;
    let packet_end = one_question_end(packet).ok()?;
    if packet[12..packet_end] != query[12..query_end] {
        return None;
    }
    Some(packet_end)
}

/// Requires every declared DNS resource record to fit within the packet.
fn has_complete_records(packet: &[u8], mut offset: usize) -> bool {
    for count_offset in [6usize, 8, 10] {
        let count = u16::from_be_bytes([packet[count_offset], packet[count_offset + 1]]);
        for _ in 0..count {
            let name_end = match skip_name(packet, offset) {
                Ok(value) => value,
                Err(_) => return false,
            };
            let record_end = match name_end.checked_add(10) {
                Some(value) if value <= packet.len() => value,
                _ => return false,
            };
            let rdata_length =
                u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
            offset = match record_end.checked_add(rdata_length) {
                Some(value) if value <= packet.len() => value,
                _ => return false,
            };
        }
    }
    offset == packet.len()
}

fn udp_exchange(
    fd: i32,
    query: &[u8],
    query_id: u16,
    answer: &mut [u8],
    deadline: i64,
    transport: &mut impl DnsTransport,
) -> Result<UdpResponse> {
    loop {
        if !poll_until(fd, DnsWait::Readable, deadline, transport)? {
            return Err(crate::Errno::TIMEDOUT);
        }
        let length = match receive_datagram(fd, answer, transport) {
            Ok(length) => length,
            Err(error) if error == crate::Errno::OVERFLOW => continue,
            Err(error)
                if error == crate::Errno::INTR
                    || error == crate::Errno::AGAIN
                    || error == crate::Errno::WOULDBLOCK =>
            {
                continue
            }
            Err(error) => return Err(error),
        };
        // Ignore short, wrong-transaction, question-mismatched, malformed,
        // and oversized packets without abandoning this nameserver. A valid
        // response can legally follow all of them on the same socket.
        let packet = &answer[..length];
        let question_end = match matching_question_end(packet, query, query_id) {
            Some(value) => value,
            None => continue,
        };
        // A truncated UDP DNS message need only preserve the header and
        // echoed question; its incomplete record body is retried over TCP.
        if packet[2] & 0x02 != 0 {
            return Ok(UdpResponse::Truncated);
        }
        if !has_complete_records(packet, question_end) {
            continue;
        }
        return Ok(UdpResponse::Complete(length));
    }
}

fn tcp_exchange(
    target: &DnsSocketAddress,
    query: &[u8],
    query_id: u16,
    answer: &mut [u8],
    deadline: i64,
    transport: &mut impl DnsTransport,
) -> Result<usize> {
    if query.len() > u16::MAX as usize || answer.len() < 12 {
        return Err(crate::Errno::MSGSIZE);
    }
    let failure = transport.stream_starting();
    let wait_failed_start = |transport: &mut _, error| {
        if matches!(failure, DnsTcpFailure::WaitUntilDeadline) {
            // Source res_msend keeps its failed TCP slot and zero UDP events
            // in the outer poll. An ignored fd represents the same real CP
            // without retaining the core's already retired UDP descriptor.
            let _ = poll_until(-1, DnsWait::Readable, deadline, transport);
        }
        Err(error)
    };
    let fd = match net::socket(target.family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) {
        Ok(fd) => fd,
        Err(error) => { transport.syscall_failed(error); return wait_failed_start(transport, error); }
    };
    transport.socket_opened(fd, DnsSocketKind::Stream);
    let started = match transport.start_tcp(fd, target, query, deadline) {
        Ok(started) => started,
        Err(error) => {
            transport.close_socket(fd);
            return wait_failed_start(transport, error);
        }
    };
    let result = (|| {
        let frame_size = query.len() + 2;
        let queued = match started {
            DnsTcpStart::Connected => 0,
            DnsTcpStart::Queued { frame_bytes } => {
                if frame_bytes > frame_size { return Err(crate::Errno::OVERFLOW); }
                if frame_bytes < frame_size && !poll_until(fd, DnsWait::Writable, deadline, transport)? {
                    return Err(crate::Errno::TIMEDOUT);
                }
                frame_bytes
            }
        };

        let frame_length = [(query.len() >> 8) as u8, query.len() as u8];
        if queued < 2 { send_all(fd, &frame_length[queued..], deadline, transport)?; }
        send_all(fd, &query[queued.saturating_sub(2)..], deadline, transport)?;

        let mut response_length_bytes = [0u8; 2];
        receive_exact(fd, &mut response_length_bytes, deadline, transport)?;
        let response_length = u16::from_be_bytes(response_length_bytes) as usize;
        if response_length < 12 || response_length > answer.len() {
            return Err(crate::Errno::MSGSIZE);
        }
        let response = &mut answer[..response_length];
        receive_exact(fd, response, deadline, transport)?;
        let question_end = matching_question_end(response, query, query_id).ok_or_else(malformed)?;
        if response[2] & 0x02 != 0 || !has_complete_records(response, question_end) {
            return Err(malformed());
        }
        Ok(response_length)
    })();
    transport.close_socket(fd);
    result
}

/// Sends a DNS query through the explicitly configured nameservers.
///
/// `query` must carry `query_id` and exactly one complete DNS question, as
/// [`encode_query`] emits. Each nameserver gets a bounded UDP deadline. Short,
/// wrong-transaction, question-mismatched, record-framing-malformed, and
/// oversized datagrams are ignored until that deadline. A response with the
/// DNS truncation bit retries the same query over length-prefixed TCP, with
/// partial I/O and connect progress charged to the same deadline. Failed
/// servers advance in configured order and the configured attempt count
/// repeats that order.
pub fn exchange(
    config: &ExchangeConfig,
    query: &[u8],
    query_id: u16,
    answer: &mut [u8],
) -> Result<usize> {
    exchange_impl(config, query, query_id, answer, false, &mut RawDnsTransport).map_err(|error| match error {
        ExchangeError::Setup(errno) | ExchangeError::Transport(errno) => errno,
    })
}

/// Distinguishes a local socket-creation failure from a failed DNS exchange.
/// The C netdb owner needs the original local errno for `EAI_SYSTEM`, while
/// the existing native [`exchange`] contract collapses exhausted attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExchangeError {
    /// A UDP socket could not be created for the selected nameserver.
    Setup(crate::Errno),
    /// Invalid input or exhausted bounded transport attempts.
    Transport(crate::Errno),
}

/// Performs [`exchange`] while preserving the first socket creation error.
/// A socket creation failure returns immediately; packet failures retain
/// the ordinary bounded retry/failover contract. No probe socket is opened.
pub fn exchange_with_setup_error(
    config: &ExchangeConfig,
    query: &[u8],
    query_id: u16,
    answer: &mut [u8],
) -> core::result::Result<usize, ExchangeError> {
    exchange_impl(config, query, query_id, answer, true, &mut RawDnsTransport)
}

/// Performs the shared DNS exchange with an explicit C cancellation/lifetime
/// owner. Socket setup errors remain distinct, as in
/// [`exchange_with_setup_error`]. Native callers retain [`exchange`].
pub fn exchange_with_transport(
    config: &ExchangeConfig,
    query: &[u8],
    query_id: u16,
    answer: &mut [u8],
    transport: &mut impl DnsTransport,
) -> core::result::Result<usize, ExchangeError> {
    exchange_impl(config, query, query_id, answer, true, transport)
}

fn exchange_impl(
    config: &ExchangeConfig,
    query: &[u8],
    query_id: u16,
    answer: &mut [u8],
    preserve_setup_error: bool,
    transport: &mut impl DnsTransport,
) -> core::result::Result<usize, ExchangeError> {
    if config.nameserver_count == 0
        || config.nameserver_count > MAX_NAMESERVERS
        || config.timeout_ms == 0
        || config.attempts == 0
        || query.len() < 12
        || answer.len() < 12
        || u16::from_be_bytes([query[0], query[1]]) != query_id
        || one_question_end(query).is_err()
    {
        return Err(ExchangeError::Transport(invalid()));
    }
    let mut attempt = 0u8;
    while attempt < config.attempts {
        let mut index = 0usize;
        while index < config.nameserver_count {
            let server = config.nameservers[index];
            let target = match server_address(server) {
                Ok(value) => value,
                Err(_) => {
                    index += 1;
                    continue;
                }
            };
            let deadline = match deadline_after(config.timeout_ms, transport) {
                Ok(value) => value,
                Err(_) => {
                    index += 1;
                    continue;
                }
            };
            let fd = match net::socket(
                server.family as i32,
                SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                0,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    transport.syscall_failed(error);
                    if preserve_setup_error { return Err(ExchangeError::Setup(error)); }
                    index += 1;
                    continue;
                }
            };
            transport.socket_opened(fd, DnsSocketKind::Datagram);
            // SAFETY: `target.storage` contains the exact initialized
            // Linux sockaddr record and remains live across the syscall.
            if let Err(error) = unsafe { net::connect_raw(fd, target.storage.as_ptr(), target.length) } {
                transport.syscall_failed(error);
                transport.close_socket(fd);
                index += 1;
                continue;
            }
            if send_datagram(fd, query, deadline, transport).is_err() {
                transport.close_socket(fd);
                index += 1;
                continue;
            }
            match udp_exchange(fd, query, query_id, answer, deadline, transport) {
                Ok(UdpResponse::Complete(length)) => {
                    transport.close_socket(fd);
                    return Ok(length);
                }
                Ok(UdpResponse::Truncated) => {
                    transport.close_socket(fd);
                    if let Ok(length) = tcp_exchange(&target, query, query_id, answer, deadline, transport)
                    {
                        return Ok(length);
                    }
                }
                Err(_) => {
                    transport.close_socket(fd);
                }
            }
            index += 1;
        }
        attempt = attempt.saturating_add(1);
    }
    Err(ExchangeError::Transport(crate::Errno::TIMEDOUT))
}
