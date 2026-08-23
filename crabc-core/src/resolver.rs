//! Stateless Linux/AArch64 resolver operations.

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

struct ServerAddress {
    family: i32,
    storage: [u8; 28],
    length: u32,
}

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

fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize> {
    let mut jumps = 0usize;
    loop {
        if offset >= packet.len() {
            return Err(malformed());
        }
        let length = packet[offset];
        if length & 0xc0 == 0xc0 {
            if offset + 1 >= packet.len() {
                return Err(malformed());
            }
            return Ok(offset + 2);
        }
        if length > 63 {
            return Err(malformed());
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        if offset + length as usize > packet.len() {
            return Err(malformed());
        }
        offset += length as usize;
        jumps += 1;
        if jumps > 128 {
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
            if offset + 1 >= packet.len() {
                return Err(malformed());
            }
            let target = ((length as usize & 0x3f) << 8) | packet[offset + 1] as usize;
            if target >= packet.len() || target == offset {
                return Err(malformed());
            }
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

fn server_address(server: NameServer) -> Result<ServerAddress> {
    let mut result = ServerAddress {
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

fn monotonic_millis() -> Result<i64> {
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: `value` is the exact two-word Linux/AArch64 timespec output
    // record and remains live for the direct syscall.
    unsafe {
        crate::time::clock_gettime_raw(CLOCK_MONOTONIC, (&mut value as *mut Timespec).cast())?
    };
    Ok(value
        .seconds
        .saturating_mul(1_000)
        .saturating_add(value.nanoseconds / 1_000_000))
}

fn deadline_after(timeout_ms: u32) -> Result<i64> {
    Ok(monotonic_millis()?.saturating_add(timeout_ms as i64))
}

fn remaining_millis(deadline: i64) -> Result<u32> {
    let now = monotonic_millis()?;
    if now >= deadline {
        return Ok(0);
    }
    Ok((deadline - now).min(u32::MAX as i64) as u32)
}

fn poll_until(fd: i32, events: i16, deadline: i64) -> Result<bool> {
    loop {
        let remaining = remaining_millis(deadline)?;
        if remaining == 0 {
            return Ok(false);
        }
        let mut poll = PollFd {
            fd,
            events,
            revents: 0,
        };
        let timeout = Timespec {
            seconds: (remaining / 1_000) as i64,
            nanoseconds: ((remaining % 1_000) as i64) * 1_000_000,
        };
        // SAFETY: `poll` and `timeout` are valid local Linux ABI records.
        match unsafe {
            crate::event::ppoll_raw(
                (&mut poll as *mut PollFd).cast(),
                1,
                (&timeout as *const Timespec).cast(),
                core::ptr::null(),
                8,
            )
        } {
            Ok(0) => return Ok(false),
            Ok(_) => {
                return Ok(poll.revents & (events | POLLERR | POLLHUP | POLLNVAL) != 0);
            }
            Err(error) if error == crate::Errno::INTR => continue,
            Err(error) => return Err(error),
        }
    }
}

fn send_all(fd: i32, bytes: &[u8], deadline: i64) -> Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if remaining_millis(deadline)? == 0 {
            return Err(crate::Errno::TIMEDOUT);
        }
        // A connected stream uses the same Linux sendto ABI with a null
        // destination; MSG_NOSIGNAL keeps a failed DNS peer from raising
        // SIGPIPE in the caller.
        let sent = unsafe {
            net::sendto_raw(
                fd,
                bytes[offset..].as_ptr(),
                bytes.len() - offset,
                MSG_NOSIGNAL,
                core::ptr::null(),
                0,
            )
        };
        match sent {
            Ok(0) => return Err(crate::Errno::PIPE),
            Ok(length) => offset += length,
            Err(error) if error == crate::Errno::INTR => continue,
            Err(error) if error == crate::Errno::AGAIN || error == crate::Errno::WOULDBLOCK => {
                if !poll_until(fd, POLLOUT, deadline)? {
                    return Err(crate::Errno::TIMEDOUT);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn send_datagram(fd: i32, bytes: &[u8], deadline: i64) -> Result<()> {
    loop {
        if remaining_millis(deadline)? == 0 {
            return Err(crate::Errno::TIMEDOUT);
        }
        // A DNS query must remain one UDP datagram. A short successful
        // send is therefore a failed server attempt, never a partial
        // query which can be retried as a second datagram.
        let sent = unsafe {
            net::sendto_raw(
                fd,
                bytes.as_ptr(),
                bytes.len(),
                MSG_NOSIGNAL,
                core::ptr::null(),
                0,
            )
        };
        match sent {
            Ok(length) if length == bytes.len() => return Ok(()),
            Ok(_) => return Err(crate::Errno::MSGSIZE),
            Err(error) if error == crate::Errno::INTR => continue,
            Err(error) if error == crate::Errno::AGAIN || error == crate::Errno::WOULDBLOCK => {
                if !poll_until(fd, POLLOUT, deadline)? {
                    return Err(crate::Errno::TIMEDOUT);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn receive_exact(fd: i32, bytes: &mut [u8], deadline: i64) -> Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if !poll_until(fd, POLLIN, deadline)? {
            return Err(crate::Errno::TIMEDOUT);
        }
        let received = unsafe {
            net::recvfrom_raw(
                fd,
                bytes[offset..].as_mut_ptr(),
                bytes.len() - offset,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        match received {
            Ok(0) => return Err(crate::Errno::CONNRESET),
            Ok(length) => offset += length,
            Err(error)
                if error == crate::Errno::INTR
                    || error == crate::Errno::AGAIN
                    || error == crate::Errno::WOULDBLOCK =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn udp_exchange(
    fd: i32,
    query_id: u16,
    answer: &mut [u8],
    deadline: i64,
) -> Result<UdpResponse> {
    loop {
        if !poll_until(fd, POLLIN, deadline)? {
            return Err(crate::Errno::TIMEDOUT);
        }
        let received = unsafe {
            net::recvfrom_raw(
                fd,
                answer.as_mut_ptr(),
                answer.len(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        let length = match received {
            Ok(length) => length,
            Err(error)
                if error == crate::Errno::INTR
                    || error == crate::Errno::AGAIN
                    || error == crate::Errno::WOULDBLOCK =>
            {
                continue
            }
            Err(error) => return Err(error),
        };
        // Ignore short, non-response, wrong-transaction, and empty-
        // question packets without abandoning this nameserver. A valid
        // response can legally follow all of them on the same socket.
        if length < 12
            || u16::from_be_bytes([answer[0], answer[1]]) != query_id
            || answer[2] & 0x80 == 0
            || u16::from_be_bytes([answer[4], answer[5]]) == 0
        {
            continue;
        }
        if answer[2] & 0x02 != 0 {
            return Ok(UdpResponse::Truncated);
        }
        return Ok(UdpResponse::Complete(length));
    }
}

fn tcp_exchange(
    target: &ServerAddress,
    query: &[u8],
    query_id: u16,
    answer: &mut [u8],
    deadline: i64,
) -> Result<usize> {
    if query.len() > u16::MAX as usize || answer.len() < 12 {
        return Err(crate::Errno::MSGSIZE);
    }
    let fd = net::socket(target.family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)?;
    let result = (|| {
        // SAFETY: `target.storage` contains the exact initialized Linux
        // sockaddr record selected by `server_address`.
        let connected = unsafe { net::connect_raw(fd, target.storage.as_ptr(), target.length) };
        match connected {
            Ok(()) => {}
            Err(error)
                if error == crate::Errno::INPROGRESS || error == crate::Errno::ALREADY =>
            {
                if !poll_until(fd, POLLOUT, deadline)? {
                    return Err(crate::Errno::TIMEDOUT);
                }
                let pending = net::socket_error(fd)?;
                if pending != 0 {
                    return Err(crate::Errno::from_raw(pending).unwrap_or(crate::Errno::IO));
                }
            }
            Err(error) => return Err(error),
        }

        let frame_length = [(query.len() >> 8) as u8, query.len() as u8];
        send_all(fd, &frame_length, deadline)?;
        send_all(fd, query, deadline)?;

        let mut response_length_bytes = [0u8; 2];
        receive_exact(fd, &mut response_length_bytes, deadline)?;
        let response_length = u16::from_be_bytes(response_length_bytes) as usize;
        if response_length < 12 || response_length > answer.len() {
            return Err(crate::Errno::MSGSIZE);
        }
        let response = &mut answer[..response_length];
        receive_exact(fd, response, deadline)?;
        if u16::from_be_bytes([response[0], response[1]]) != query_id
            || response[2] & 0x80 == 0
            || u16::from_be_bytes([response[4], response[5]]) == 0
            || response[2] & 0x02 != 0
        {
            return Err(malformed());
        }
        Ok(response_length)
    })();
    let _ = crate::io::close(fd);
    result
}

/// Sends a DNS query through the explicitly configured nameservers.
///
/// Each nameserver gets a bounded UDP deadline. Short, malformed, and
/// wrong-transaction datagrams are ignored until that deadline. A
/// response with the DNS truncation bit retries the same query over
/// length-prefixed TCP, with partial I/O and connect progress charged to
/// the same deadline. Failed servers advance in configured order and the
/// configured attempt count repeats that order.
pub fn exchange(
    config: &ExchangeConfig,
    query: &[u8],
    query_id: u16,
    answer: &mut [u8],
) -> Result<usize> {
    if config.nameserver_count == 0
        || config.nameserver_count > MAX_NAMESERVERS
        || config.timeout_ms == 0
        || config.attempts == 0
        || query.len() < 12
        || answer.len() < 12
    {
        return Err(invalid());
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
            let deadline = match deadline_after(config.timeout_ms) {
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
                Err(_) => {
                    index += 1;
                    continue;
                }
            };
            // SAFETY: `target.storage` contains the exact initialized
            // Linux sockaddr record and remains live across the syscall.
            if unsafe { net::connect_raw(fd, target.storage.as_ptr(), target.length) }.is_err()
            {
                let _ = crate::io::close(fd);
                index += 1;
                continue;
            }
            if send_datagram(fd, query, deadline).is_err() {
                let _ = crate::io::close(fd);
                index += 1;
                continue;
            }
            match udp_exchange(fd, query_id, answer, deadline) {
                Ok(UdpResponse::Complete(length)) => {
                    let _ = crate::io::close(fd);
                    return Ok(length);
                }
                Ok(UdpResponse::Truncated) => {
                    let _ = crate::io::close(fd);
                    if let Ok(length) = tcp_exchange(&target, query, query_id, answer, deadline)
                    {
                        return Ok(length);
                    }
                }
                Err(_) => {
                    let _ = crate::io::close(fd);
                }
            }
            index += 1;
        }
        attempt = attempt.saturating_add(1);
    }
    Err(crate::Errno::TIMEDOUT)
}
