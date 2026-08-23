//! Direct Linux socket and address operations.
//!
//! Socket descriptors and allocation-free IPv4/IPv6 endpoint values cross the
//! native Rust boundary without libc's resolver, public C ABI, or process-global
//! state. The resolver facade re-exports the endpoint values for compatibility.

use bitflags::bitflags;
use core::cmp::min;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{size_of, MaybeUninit};
/// The standard no-std IP value types used by Rustix-compatible APIs.
pub use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::num::NonZeroU32;
use core::slice;

use crate::buffer::Buffer;
use crate::io::IoSlice;
use crate::{AsFd, OwnedFd, Result};

/// Linux network-device ioctl operations.
#[path = "netdevice.rs"]
pub mod netdevice;

/// Explicit, bounded `/etc/ethers` parsing and native IPv6 constants.
#[path = "ethers.rs"]
pub mod ethers;

/// Parses musl's legacy IPv4 number syntax into an owned address value.
///
/// The input is a complete, length-delimited byte slice rather than an
/// implicit NUL-terminated C string. It accepts one through four numeric
/// components, with the same base-zero decimal, octal, and hexadecimal
/// interpretation as musl's `inet_aton`; component widths are therefore
/// 32-bit, 8/24-bit, 8/8/16-bit, or 8/8/8/8-bit respectively. The result is
/// stored as the four network-order address octets in [`Ipv4Addr`].
///
/// This is deliberately separate from [`IpAddress::parse`], whose modern
/// presentation syntax accepts only four dotted-decimal components. Invalid
/// input, including non-ASCII bytes, whitespace, signs, NUL bytes, trailing
/// data, and overflowing components, returns `None`. No allocation, libc
/// call, C ABI, or TLS `errno` state is involved.
#[must_use]
pub fn parse_ipv4_legacy(value: &[u8]) -> Option<Ipv4Addr> {
    let mut parts = [0u64; 4];
    let mut count = 0usize;
    let mut start = 0usize;

    loop {
        let (part, consumed) = parse_ipv4_legacy_part(&value[start..])?;
        if count == parts.len() {
            return None;
        }
        parts[count] = part;
        count += 1;

        if consumed == value.len() - start {
            break;
        }
        if value[start + consumed] != b'.' {
            return None;
        }
        start += consumed + 1;
        if start == value.len() {
            return None;
        }
    }

    match count {
        1 => {
            // Musl's switch intentionally falls through all three cases for
            // a single component, making it a complete 32-bit network-order
            // word rather than four independent octets.
            let value = u32::try_from(parts[0]).ok()?;
            Some(Ipv4Addr::from(value.to_be_bytes()))
        }
        2 => {
            if parts[0] > u8::MAX as u64 || parts[1] > 0x00ff_ffff {
                return None;
            }
            Some(Ipv4Addr::new(
                parts[0] as u8,
                (parts[1] >> 16) as u8,
                (parts[1] >> 8) as u8,
                parts[1] as u8,
            ))
        }
        3 => {
            if parts[0] > u8::MAX as u64 || parts[1] > u8::MAX as u64 || parts[2] > 0x0000_ffff {
                return None;
            }
            Some(Ipv4Addr::new(
                parts[0] as u8,
                parts[1] as u8,
                (parts[2] >> 8) as u8,
                parts[2] as u8,
            ))
        }
        4 => {
            if parts.iter().any(|&part| part > u8::MAX as u64) {
                return None;
            }
            Some(Ipv4Addr::new(
                parts[0] as u8,
                parts[1] as u8,
                parts[2] as u8,
                parts[3] as u8,
            ))
        }
        _ => None,
    }
}

/// Parses a musl legacy IPv4 number into its host-order network number.
///
/// This is the allocation-free native counterpart of musl's
/// `inet_network`. The C interface returns `0xffffffff` for both malformed
/// input and the valid all-ones address; `Option` keeps those cases distinct
/// here. The returned integer is in host order, while the address parsed by
/// [`parse_ipv4_legacy`] is in network byte order.
#[must_use]
pub fn parse_ipv4_network_number(value: &[u8]) -> Option<u32> {
    parse_ipv4_legacy(value).map(|address| u32::from_be_bytes(address.octets()))
}

/// Builds a network-byte-order IPv4 address from classful host-order numbers.
///
/// This follows the classful `inet_makeaddr` contract: a network number below
/// 128 is a class-A number, one below 65536 is class B and receives the
/// `0x8000_0000` class marker, one below 0x1000000 is class C and receives the
/// `0xc000_0000` marker, and every larger number receives the
/// `0xe000_0000` marker. The host number is ORed into the result without
/// masking. The result is converted back to logical network-order octets.
#[must_use]
pub fn make_ipv4_address(network_number: u32, local_number: u32) -> Ipv4Addr {
    let network_word = if network_number < 128 {
        network_number << 24
    } else if network_number < 65_536 {
        network_number.wrapping_shl(16) | 0x8000_0000
    } else if network_number < 0x0100_0000 {
        network_number.wrapping_shl(8) | 0xc000_0000
    } else {
        network_number | 0xe000_0000
    };
    Ipv4Addr::from((local_number | network_word).to_be_bytes())
}

/// Returns musl's classful local-address component in host byte order.
///
/// The logical network-order address is first converted to its host-order
/// word, matching musl's `ntohl(in.s_addr)` boundary. This is a legacy
/// classful operation, not modern CIDR classification.
#[must_use]
pub fn ipv4_local_number(address: Ipv4Addr) -> u32 {
    let raw = u32::from_be_bytes(address.octets());
    if raw >> 24 < 128 {
        raw & 0x00ff_ffff
    } else if raw >> 24 < 192 {
        raw & 0x0000_ffff
    } else {
        raw & 0x0000_00ff
    }
}

/// Returns musl's classful network component in host byte order.
///
/// See [`ipv4_local_number`] for the host-order conversion boundary.
#[must_use]
pub fn ipv4_network_number(address: Ipv4Addr) -> u32 {
    let raw = u32::from_be_bytes(address.octets());
    if raw >> 24 < 128 {
        raw >> 24
    } else if raw >> 24 < 192 {
        raw >> 16
    } else {
        raw >> 8
    }
}

fn parse_ipv4_legacy_part(value: &[u8]) -> Option<(u64, usize)> {
    let first = *value.first()?;
    if !first.is_ascii_digit() {
        return None;
    }

    let (base, mut index) = if first == b'0' {
        if value.get(1).copied() == Some(b'x') || value.get(1).copied() == Some(b'X') {
            (16u64, 2usize)
        } else {
            (8u64, 0usize)
        }
    } else {
        (10u64, 0usize)
    };
    let digit_start = index;
    let mut result = 0u64;

    while index < value.len() {
        let digit = match (base, value[index]) {
            (16, b'0'..=b'9') => Some(value[index] - b'0'),
            (16, b'a'..=b'f') => Some(value[index] - b'a' + 10),
            (16, b'A'..=b'F') => Some(value[index] - b'A' + 10),
            (10, b'0'..=b'9') => Some(value[index] - b'0'),
            (8, b'0'..=b'7') => Some(value[index] - b'0'),
            _ => None,
        };
        let Some(digit) = digit else { break };
        result = result.checked_mul(base)?.checked_add(digit as u64)?;
        index += 1;
    }

    if index == digit_start {
        return None;
    }
    Some((result, index))
}

/// An owned six-octet Ethernet (MAC) address.
///
/// The value is independent of the C `struct ether_addr` layout and owns no
/// process-global conversion buffer. [`Self::parse`] accepts the useful
/// `ether_aton_r` grammar—six colon-separated hexadecimal numbers, including
/// one-digit values and the `0x` prefix accepted by `strtoul(..., 16)`—from a
/// complete byte slice. Each component must contain at least one digit and fit
/// in one octet; this explicit requirement rejects C's
/// no-conversion/empty-component edge case instead of turning it into an
/// accidental zero. The native address grammar deliberately excludes
/// `strtoul`'s generic leading whitespace and sign conveniences: those are not
/// address spellings. Trailing whitespace or any other trailing byte is
/// likewise rejected by the complete-slice contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct EthernetAddress([u8; 6]);

impl EthernetAddress {
    /// Creates an Ethernet address from its six wire-order octets.
    #[must_use]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Returns the six octets in wire order.
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Parses a complete musl-style colon-separated Ethernet address.
    ///
    /// The length-delimited input must contain exactly six components and no
    /// NUL terminator or trailing data. Failure is represented by `None`, so
    /// this native API has no C static result, allocation, or TLS `errno`
    /// interaction. Parsing writes no caller storage and never partially
    /// publishes an address.
    #[must_use]
    pub fn parse(value: &[u8]) -> Option<Self> {
        let mut octets = [0u8; 6];
        let mut cursor = 0usize;
        for (index, octet) in octets.iter_mut().enumerate() {
            if index != 0 {
                if value.get(cursor).copied() != Some(b':') {
                    return None;
                }
                cursor += 1;
            }
            let (parsed, consumed) = parse_ethernet_component(&value[cursor..])?;
            *octet = parsed;
            cursor += consumed;
        }
        (cursor == value.len()).then_some(Self(octets))
    }

    /// Returns musl's canonical two-digit uppercase hexadecimal spelling.
    ///
    /// The returned `[u8; 17]` is an owned, non-NUL-terminated ASCII value:
    /// six two-digit components and five colons. It replaces `ether_ntoa`'s
    /// process-static buffer without requiring an allocator or caller-owned
    /// mutable storage.
    #[must_use]
    pub const fn to_ascii_bytes(self) -> [u8; 17] {
        let digits = *b"0123456789ABCDEF";
        let mut output = [0u8; 17];
        let mut index = 0usize;
        while index < 6 {
            let output_index = index * 3;
            let value = self.0[index];
            output[output_index] = digits[(value >> 4) as usize];
            output[output_index + 1] = digits[(value & 0x0f) as usize];
            if index != 5 {
                output[output_index + 2] = b':';
            }
            index += 1;
        }
        output
    }

    /// Writes the canonical spelling into caller-provided storage.
    ///
    /// At least 17 bytes are required. The operation is all-or-nothing: a
    /// short destination is rejected before any byte is changed, and success
    /// returns the 17 bytes written. No terminating NUL is written.
    pub fn write_to(self, destination: &mut [u8]) -> Option<usize> {
        if destination.len() < 17 {
            return None;
        }
        destination[..17].copy_from_slice(&self.to_ascii_bytes());
        Some(17)
    }
}

impl fmt::Display for EthernetAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.to_ascii_bytes();
        // SAFETY: `to_ascii_bytes` contains only ASCII bytes, so this is valid
        // UTF-8 and remains entirely within the formatter's borrowed output.
        let text = unsafe { core::str::from_utf8_unchecked(&text) };
        formatter.write_str(text)
    }
}

fn parse_ethernet_component(value: &[u8]) -> Option<(u8, usize)> {
    let mut index = 0usize;
    let prefixed = value.get(index).copied() == Some(b'0')
        && matches!(value.get(index + 1).copied(), Some(b'x' | b'X'))
        && value
            .get(index + 2)
            .copied()
            .is_some_and(|byte| ethernet_hex_digit(byte).is_some());
    if prefixed {
        index += 2;
    }

    let digits_start = index;
    let mut number = 0u64;
    while let Some(byte) = value.get(index).copied() {
        let Some(digit) = ethernet_hex_digit(byte) else {
            break;
        };
        number = number.checked_mul(16)?.checked_add(digit as u64)?;
        index += 1;
    }
    if index == digits_start {
        // `0x` without a following digit follows strtoul's no-conversion
        // behavior, but this bounded API rejects that malformed component.
        return None;
    }

    if number > u8::MAX as u64 {
        return None;
    }
    Some((number as u8, index))
}

#[inline]
fn ethernet_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// An owned IPv4 or IPv6 address represented in network byte order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpAddress {
    /// An IPv4 address.
    V4([u8; 4]),
    /// An IPv6 address.
    V6([u8; 16]),
}

impl IpAddress {
    /// Parses a presentation-format IPv4 or IPv6 address without libc.
    #[must_use]
    pub fn parse(value: &[u8]) -> Option<Self> {
        parse_ipv4(value)
            .map(Self::V4)
            .or_else(|| parse_ipv6(value).map(Self::V6))
    }

    /// Returns the corresponding Linux address family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        match self {
            Self::V4(_) => AddressFamily::INET,
            Self::V6(_) => AddressFamily::INET6,
        }
    }

    /// Returns the address bytes in network order.
    #[must_use]
    pub const fn octets(self) -> [u8; 16] {
        match self {
            Self::V4(value) => [
                value[0], value[1], value[2], value[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            Self::V6(value) => value,
        }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4(bytes) => write!(
                formatter,
                "{}.{}.{}.{}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            ),
            Self::V6(bytes) => fmt_ipv6(formatter, bytes),
        }
    }
}

/// A typed IP endpoint represented without a C socket-address pointer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SocketAddress {
    address: IpAddress,
    port: u16,
    scope_id: u32,
}

impl SocketAddress {
    /// Creates an endpoint with a host-order port.
    #[must_use]
    pub const fn new(address: IpAddress, port: u16) -> Self {
        Self {
            address,
            port,
            scope_id: 0,
        }
    }

    /// Creates an IPv6 endpoint with an interface scope identifier.
    ///
    /// A nonzero scope is meaningful only for IPv6. [`connect`] rejects an
    /// IPv4 endpoint carrying a nonzero scope instead of silently discarding
    /// it.
    #[must_use]
    pub const fn new_scoped(address: IpAddress, port: u16, scope_id: u32) -> Self {
        Self {
            address,
            port,
            scope_id,
        }
    }

    /// Returns the endpoint's IP address.
    #[must_use]
    pub const fn ip(self) -> IpAddress {
        self.address
    }

    /// Returns the endpoint's host-order port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    /// Returns the IPv6 scope identifier, or zero for IPv4.
    #[must_use]
    pub const fn scope_id(self) -> u32 {
        self.scope_id
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            IpAddress::V4(_) => write!(formatter, "{}:{}", self.address, self.port),
            IpAddress::V6(_) if self.scope_id == 0 => {
                write!(formatter, "[{}]:{}", self.address, self.port)
            }
            IpAddress::V6(_) => write!(
                formatter,
                "[{}%{}]:{}",
                self.address, self.scope_id, self.port
            ),
        }
    }
}

/// An owned 16-bit value in Internet/network byte order.
///
/// The representation is explicitly two big-endian bytes rather than a host
/// integer. This keeps byte order visible at serialization boundaries and
/// makes the value safe to borrow as a packet or socket-address field without
/// relying on the target's native endianness. It is the typed native
/// counterpart of the value-only part of C's `htons`/`ntohs` operations; it
/// does not expose a C ABI, global error state, or a destination buffer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct NetworkU16([u8; 2]);

impl NetworkU16 {
    /// Encodes a host-order value as network-order bytes.
    #[must_use]
    pub const fn from_host(value: u16) -> Self {
        Self(value.to_be_bytes())
    }

    /// Wraps an already network-order byte sequence.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 2]) -> Self {
        Self(bytes)
    }

    /// Decodes the value into host byte order.
    #[must_use]
    pub const fn to_host(self) -> u16 {
        u16::from_be_bytes(self.0)
    }

    /// Returns the exact network-order bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 2] {
        self.0
    }
}

/// An owned 32-bit value in Internet/network byte order.
///
/// See [`NetworkU16`] for the boundary contract. This is the typed native
/// counterpart of the value-only part of C's `htonl`/`ntohl` operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct NetworkU32([u8; 4]);

impl NetworkU32 {
    /// Encodes a host-order value as network-order bytes.
    #[must_use]
    pub const fn from_host(value: u32) -> Self {
        Self(value.to_be_bytes())
    }

    /// Wraps an already network-order byte sequence.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Decodes the value into host byte order.
    #[must_use]
    pub const fn to_host(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// Returns the exact network-order bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0
    }
}

/// A raw Linux socket address-family number.
pub type RawAddressFamily = u16;

/// Linux `AF_*` values used by socket constructors.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AddressFamily(RawAddressFamily);

impl AddressFamily {
    /// `AF_UNSPEC`.
    pub const UNSPEC: Self = Self(0);
    /// `AF_UNIX`, also known as `AF_LOCAL`.
    pub const UNIX: Self = Self(1);
    /// `AF_INET`.
    pub const INET: Self = Self(2);
    /// `AF_INET6`.
    pub const INET6: Self = Self(10);

    /// Constructs an address family from its Linux ABI value.
    #[inline]
    pub const fn from_raw(raw: RawAddressFamily) -> Self {
        Self(raw)
    }

    /// Returns the Linux ABI value.
    #[inline]
    pub const fn as_raw(self) -> RawAddressFamily {
        self.0
    }
}

/// A raw Linux socket-type number.
pub type RawSocketType = u32;

/// Linux `SOCK_*` socket types.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct SocketType(RawSocketType);

impl SocketType {
    /// `SOCK_STREAM`.
    pub const STREAM: Self = Self(1);
    /// `SOCK_DGRAM`.
    pub const DGRAM: Self = Self(2);
    /// `SOCK_SEQPACKET`.
    pub const SEQPACKET: Self = Self(5);
    /// `SOCK_RAW`.
    pub const RAW: Self = Self(3);
    /// `SOCK_RDM`.
    pub const RDM: Self = Self(4);

    /// Constructs a socket type from its Linux ABI value.
    #[inline]
    pub const fn from_raw(raw: RawSocketType) -> Self {
        Self(raw)
    }

    /// Returns the Linux ABI value.
    #[inline]
    pub const fn as_raw(self) -> RawSocketType {
        self.0
    }
}

/// Typed Linux socket-option queries.
pub mod sockopt {
    use super::{AddressFamily, Protocol, SocketType};
    use crate::{AsFd, Result};
    use core::num::NonZeroU32;

    /// Reads Linux `SOL_SOCKET/SO_TYPE` from a borrowed socket descriptor.
    ///
    /// The returned [`SocketType`] preserves the kernel's raw socket-type
    /// value, including values added by a newer Linux ABI. The option level,
    /// name, output storage, and length remain fixed inside the direct syscall
    /// seam; descriptor errors are returned as [`crate::Errno`] values without
    /// C `errno` or a libc fallback.
    #[inline]
    pub fn socket_type<Fd: AsFd>(fd: Fd) -> Result<SocketType> {
        crabc_core::net::socket_type(fd.as_fd().as_raw_fd()).map(SocketType::from_raw)
    }

    /// Reads Linux `SOL_SOCKET/SO_PROTOCOL` from a borrowed socket descriptor.
    ///
    /// Linux reports the protocol as a four-byte integer. Zero maps to
    /// `None`, while nonzero values preserve Rustix's raw `Protocol` word.
    /// Descriptor errors are returned as [`crate::Errno`]
    /// values without C `errno` or a libc fallback.
    #[inline]
    pub fn socket_protocol<Fd: AsFd>(fd: Fd) -> Result<Option<Protocol>> {
        crabc_core::net::socket_protocol(fd.as_fd().as_raw_fd())
            .map(|raw| NonZeroU32::new(raw).map(Protocol::from_raw))
    }

    /// Reads Linux `SOL_SOCKET/SO_COOKIE` from a borrowed socket descriptor.
    ///
    /// The kernel's 64-bit cookie is returned unchanged. Repeated reads on a
    /// live socket observe the same value, but callers should not infer any
    /// stronger lifetime or global-uniqueness guarantee from this borrowed
    /// observation. Descriptor and option errors remain [`crate::Errno`]
    /// values without C `errno` or a libc fallback.
    #[inline]
    #[doc(alias = "SO_COOKIE")]
    pub fn socket_cookie<Fd: AsFd>(fd: Fd) -> Result<u64> {
        crabc_core::net::socket_cookie(fd.as_fd().as_raw_fd())
    }

    /// Reads Linux `SOL_SOCKET/SO_DOMAIN` from a borrowed socket descriptor.
    ///
    /// The kernel's signed four-byte family is converted to the existing
    /// raw-preserving `AddressFamily` type. Negative or out-of-range kernel
    /// values map to [`crate::Errno::OPNOTSUPP`], matching Rustix; descriptor
    /// and option errors remain direct [`crate::Errno`] values.
    #[inline]
    #[doc(alias = "SO_DOMAIN")]
    pub fn socket_domain<Fd: AsFd>(fd: Fd) -> Result<AddressFamily> {
        let raw = crabc_core::net::socket_domain(fd.as_fd().as_raw_fd())?;
        let raw = u16::try_from(raw).map_err(|_| crate::Errno::OPNOTSUPP)?;
        Ok(AddressFamily::from_raw(raw))
    }

    /// Reads Linux `SOL_SOCKET/SO_ACCEPTCONN` from a borrowed socket
    /// descriptor.
    ///
    /// Linux represents the listening state as a four-byte integer; any
    /// nonzero kernel value is `true`, matching Rustix. The query observes
    /// state changed by [`crate::net::listen`] but does not change it itself.
    #[inline]
    #[doc(alias = "SO_ACCEPTCONN")]
    pub fn socket_acceptconn<Fd: AsFd>(fd: Fd) -> Result<bool> {
        crabc_core::net::socket_acceptconn(fd.as_fd().as_raw_fd()).map(|raw| raw != 0)
    }

    /// Sets Linux `SOL_SOCKET/SO_BROADCAST` on a borrowed socket descriptor.
    ///
    /// The option is represented as a Rust `bool`; Linux receives the
    /// required four-byte integer encoding inside the direct syscall seam.
    /// Kernel failures are returned as [`crate::Errno`] values without C
    /// `errno` or a libc fallback.
    #[inline]
    #[doc(alias = "SO_BROADCAST")]
    pub fn set_socket_broadcast<Fd: AsFd>(fd: Fd, enabled: bool) -> Result<()> {
        crabc_core::net::set_socket_broadcast(fd.as_fd().as_raw_fd(), enabled)
    }

    /// Reads Linux `SOL_SOCKET/SO_BROADCAST` from a borrowed socket
    /// descriptor.
    ///
    /// A nonzero Linux option value is returned as `true`. The option level,
    /// name, output storage, and length are fixed inside the direct syscall
    /// seam, so callers cannot provide arbitrary socket-option pointers.
    #[inline]
    #[doc(alias = "SO_BROADCAST")]
    pub fn socket_broadcast<Fd: AsFd>(fd: Fd) -> Result<bool> {
        crabc_core::net::socket_broadcast(fd.as_fd().as_raw_fd())
    }

    /// Sets Linux `SOL_SOCKET/SO_OOBINLINE` on a borrowed socket descriptor.
    ///
    /// The option is represented as a Rust `bool`; Linux receives the
    /// required four-byte integer encoding inside the direct syscall seam.
    /// Kernel failures are returned as [`crate::Errno`] values without C
    /// `errno` or a libc fallback.
    #[inline]
    #[doc(alias = "SO_OOBINLINE")]
    pub fn set_socket_oobinline<Fd: AsFd>(fd: Fd, enabled: bool) -> Result<()> {
        crabc_core::net::set_socket_oobinline(fd.as_fd().as_raw_fd(), enabled)
    }

    /// Reads Linux `SOL_SOCKET/SO_OOBINLINE` from a borrowed socket
    /// descriptor.
    ///
    /// A nonzero Linux option value is returned as `true`. The option level,
    /// name, output storage, and length are fixed inside the direct syscall
    /// seam, so callers cannot provide arbitrary socket-option pointers.
    #[inline]
    #[doc(alias = "SO_OOBINLINE")]
    pub fn socket_oobinline<Fd: AsFd>(fd: Fd) -> Result<bool> {
        crabc_core::net::socket_oobinline(fd.as_fd().as_raw_fd())
    }
}

/// A raw, non-default Linux protocol number.
///
/// The socket syscalls receive this word bit-for-bit through their Linux C
/// `int` register slot, matching Rustix. Keeping the public representation
/// unsigned avoids changing an unrecognized kernel protocol number's bits.
pub type RawProtocol = NonZeroU32;

/// A non-default Linux socket protocol.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Protocol(RawProtocol);

impl Protocol {
    /// Constructs a protocol from a nonzero raw Linux protocol word.
    #[inline]
    pub const fn from_raw(raw: RawProtocol) -> Self {
        Self(raw)
    }

    /// Returns the nonzero Linux ABI value.
    #[inline]
    pub const fn as_raw(self) -> RawProtocol {
        self.0
    }
}

bitflags! {
    /// Socket flags accepted by Linux `socket`, `socketpair`, and `accept4`.
    ///
    /// This is intentionally a closed set. Use [`SocketFlags::from_bits`] to
    /// validate a raw flag word; unknown bits are rejected instead of being
    /// silently forwarded to the kernel. `from_bits_retain` remains available
    /// as an explicit escape hatch for callers tracking a newer Linux ABI.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SocketFlags: u32 {
        /// `SOCK_NONBLOCK`.
        const NONBLOCK = 0x0000_0800;
        /// `SOCK_CLOEXEC`.
        const CLOEXEC = 0x0008_0000;
    }
}

/// A borrowed mutable message segment for [`recvmsg`].
///
/// The segment may be built from initialized storage with [`Self::new`] or
/// from `MaybeUninit` storage with [`Self::new_uninit`]. The wrapper exposes no
/// byte slice before a receive has established how many bytes the kernel
/// initialized; use [`RecvMsg::initialized_segments`] on the successful
/// result to obtain only initialized prefixes. Segments retain their original
/// exclusive borrows for the duration of the message operation.
#[repr(transparent)]
pub struct MsgIoSliceMut<'a> {
    iovec: crabc_core::io::Iovec,
    _lifetime: PhantomData<&'a mut [MaybeUninit<u8>]>,
}

impl<'a> MsgIoSliceMut<'a> {
    /// Borrows initialized byte storage as one receive-message segment.
    #[inline]
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            iovec: crabc_core::io::Iovec {
                iov_base: buffer.as_mut_ptr(),
                iov_len: buffer.len(),
            },
            _lifetime: PhantomData,
        }
    }

    /// Borrows potentially uninitialized byte storage as one receive-message
    /// segment. Only the prefix reported by [`RecvMsg::initialized_segments`]
    /// becomes available as `&mut [u8]` after a successful receive.
    #[inline]
    pub fn new_uninit(buffer: &'a mut [MaybeUninit<u8>]) -> Self {
        Self {
            iovec: crabc_core::io::Iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            },
            _lifetime: PhantomData,
        }
    }
}

/// One private Linux/AArch64 `mmsghdr` record used by [`sendmmsg`] and
/// [`recvmmsg`].
///
/// The public wrapper deliberately contains no C header, ancillary buffer, or
/// raw pointer API. A send record borrows its [`IoSlice`] array; a receive
/// record borrows its [`MsgIoSliceMut`] array. The record is exactly the
/// kernel's 64-byte AArch64 shape so a slice of wrappers can be passed to the
/// direct syscall without a temporary allocation.
#[repr(C)]
struct MMsgHeader {
    name: *mut u8,
    name_length: u32,
    _name_padding: u32,
    iovecs: *mut crabc_core::io::Iovec,
    iovec_count: usize,
    control: *mut u8,
    control_length: usize,
    flags: u32,
    _flags_padding: u32,
    message_length: u32,
    _message_padding: u32,
}

const _: () = assert!(core::mem::size_of::<MMsgHeader>() == 64);

/// A borrowed Linux batched-message record.
///
/// Construct records with [`Self::new_send`] or [`Self::new_recv`], then pass
/// a mutable slice to [`sendmmsg`] or [`recvmmsg`]. The wrapper's lifetime
/// marker keeps every nested iovec and byte buffer alive through the syscall;
/// it does not expose the kernel record layout to callers.
#[repr(transparent)]
pub struct MMsgHdr<'a> {
    raw: MMsgHeader,
    _lifetime: PhantomData<&'a mut ()>,
}

impl<'a> MMsgHdr<'a> {
    /// Builds one outgoing message with no destination address or ancillary
    /// data. `sendmmsg` preserves the kernel's per-record byte count, which is
    /// available through [`Self::bytes`].
    #[inline]
    pub fn new_send(iovecs: &'a [IoSlice<'a>]) -> Self {
        let pointer = if iovecs.is_empty() {
            core::ptr::null_mut()
        } else {
            iovecs.as_ptr().cast::<crabc_core::io::Iovec>().cast_mut()
        };
        Self {
            raw: MMsgHeader {
                name: core::ptr::null_mut(),
                name_length: 0,
                _name_padding: 0,
                iovecs: pointer,
                iovec_count: iovecs.len(),
                control: core::ptr::null_mut(),
                control_length: 0,
                flags: 0,
                _flags_padding: 0,
                message_length: 0,
                _message_padding: 0,
            },
            _lifetime: PhantomData,
        }
    }

    /// Builds one incoming message with no source-address or ancillary-data
    /// output. Only the prefixes described by [`Self::initialized_segments`]
    /// become readable after a successful receive.
    #[inline]
    pub fn new_recv(buffers: &'a mut [MsgIoSliceMut<'a>]) -> Self {
        let pointer = if buffers.is_empty() {
            core::ptr::null_mut()
        } else {
            buffers.as_mut_ptr().cast::<crabc_core::io::Iovec>()
        };
        Self {
            raw: MMsgHeader {
                name: core::ptr::null_mut(),
                name_length: 0,
                _name_padding: 0,
                iovecs: pointer,
                iovec_count: buffers.len(),
                control: core::ptr::null_mut(),
                control_length: 0,
                flags: 0,
                _flags_padding: 0,
                message_length: 0,
                _message_padding: 0,
            },
            _lifetime: PhantomData,
        }
    }

    /// Returns the number of bytes reported for this record by Linux.
    ///
    /// For an outgoing record this is the number sent. For an incoming
    /// datagram with `RecvFlags::TRUNC`, it may exceed the initialized buffer
    /// capacity, matching Linux's `MSG_TRUNC` contract.
    #[inline]
    pub const fn bytes(&self) -> usize {
        self.raw.message_length as usize
    }

    /// Returns message flags written by Linux for an incoming record.
    #[inline]
    pub const fn flags(&self) -> RecvFlags {
        RecvFlags::from_bits_retain(self.raw.flags)
    }

    /// Yields initialized prefixes from the receive buffers used to construct
    /// this record.
    ///
    /// # Safety
    ///
    /// This must only be called on a record built by [`Self::new_recv`], after
    /// the kernel has successfully completed that record. The constructor
    /// retains the exclusive buffer borrow through the record lifetime, so
    /// reconstructing the slice from the private iovec pointer cannot alias a
    /// caller-visible mutable slice. A receive that reports `MSG_TRUNC` still
    /// exposes no bytes beyond caller storage.
    #[inline]
    pub unsafe fn initialized_segments<'buffers>(
        &'buffers mut self,
    ) -> InitializedMsgSegments<'buffers, 'a> {
        let buffers = if self.raw.iovec_count == 0 {
            // SAFETY: A dangling pointer is valid for a zero-length slice and
            // avoids constructing a Rust slice from the null empty-record
            // pointer passed to Linux.
            unsafe {
                slice::from_raw_parts_mut(
                    core::ptr::NonNull::<MsgIoSliceMut<'a>>::dangling().as_ptr(),
                    0,
                )
            }
        } else {
            // SAFETY: `new_recv` installed a pointer to this exact borrowed,
            // contiguous MsgIoSliceMut array and retained its lifetime.
            unsafe {
                slice::from_raw_parts_mut(
                    self.raw.iovecs.cast::<MsgIoSliceMut<'a>>(),
                    self.raw.iovec_count,
                )
            }
        };
        let mut capacity = 0usize;
        for buffer in buffers.iter() {
            capacity = capacity.saturating_add(buffer.iovec.iov_len);
        }
        InitializedMsgSegments {
            buffers: buffers.iter_mut(),
            remaining: min(capacity, self.bytes()),
        }
    }
}

/// The successful result of one [`recvmsg`] operation.
///
/// `bytes` preserves Linux's return value, which may exceed the supplied
/// vectored capacity when [`RecvFlags::TRUNC`] is requested. The iterator from
/// [`initialized_segments`](Self::initialized_segments) yields only the
/// prefixes actually initialized in caller storage, in segment order.
pub struct RecvMsg<'a> {
    buffers: &'a mut [MsgIoSliceMut<'a>],
    /// Linux's message byte count before any datagram truncation.
    pub bytes: usize,
    initialized: usize,
    /// Linux flags reported in the received message header.
    pub flags: RecvFlags,
}

impl<'a> RecvMsg<'a> {
    /// Returns Linux's message byte count before any datagram truncation.
    #[inline]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Returns Linux flags reported in the received message header.
    ///
    /// This is separate from the [`RecvFlags`] argument supplied to
    /// [`recvmsg`]. Unknown kernel-defined bits are preserved with
    /// `from_bits_retain` semantics.
    #[inline]
    pub const fn flags(&self) -> RecvFlags {
        self.flags
    }

    /// Iterates over initialized prefixes of the receive segments.
    ///
    /// The iterator's items are disjoint mutable slices in the same order as
    /// the supplied segments. A segment after the initialized prefix is
    /// yielded as an empty slice; its `MaybeUninit` suffix is never exposed as
    /// initialized data.
    #[inline]
    pub fn initialized_segments(&mut self) -> InitializedMsgSegments<'_, 'a> {
        InitializedMsgSegments {
            buffers: self.buffers.iter_mut(),
            remaining: self.initialized,
        }
    }
}

/// Iterator over the initialized prefixes of a successful [`RecvMsg`].
pub struct InitializedMsgSegments<'segments, 'buffer> {
    buffers: slice::IterMut<'segments, MsgIoSliceMut<'buffer>>,
    remaining: usize,
}

impl<'segments, 'buffer> Iterator for InitializedMsgSegments<'segments, 'buffer> {
    type Item = &'segments mut [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let buffer = self.buffers.next()?;
        let length = min(buffer.iovec.iov_len, self.remaining);
        self.remaining -= length;
        // A slice pointer is non-null even for an empty Rust slice, but use a
        // canonical dangling pointer for an empty segment to make that ABI
        // requirement explicit before constructing the result slice.
        let pointer = if length == 0 {
            core::ptr::NonNull::<u8>::dangling().as_ptr()
        } else {
            buffer.iovec.iov_base
        };
        // SAFETY: Each segment was created from an exclusive borrow, and
        // `IterMut` yields each wrapper at most once. The kernel initialized
        // exactly the first `length` bytes represented here.
        Some(unsafe { slice::from_raw_parts_mut(pointer, length) })
    }
}

fn checked_socket_flags(flags: SocketFlags) -> Result<u32> {
    SocketFlags::from_bits(flags.bits())
        .map(|flags| flags.bits())
        .ok_or(crate::Errno::INVAL)
}

/// Direction to disable with [`shutdown`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum Shutdown {
    /// Disable further receives.
    Read = 0,
    /// Disable further sends.
    Write = 1,
    /// Disable both receives and sends.
    Both = 2,
}

impl Shutdown {
    /// Returns the Linux `shutdown(2)` mode value.
    #[inline]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

bitflags! {
    /// Linux `MSG_*` flags accepted by [`send`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SendFlags: u32 {
        /// `MSG_OOB`.
        const OOB = 0x1;
        /// `MSG_DONTROUTE`.
        const DONTROUTE = 0x4;
        /// `MSG_DONTWAIT`.
        const DONTWAIT = 0x40;
        /// `MSG_EOR`.
        const EOR = 0x80;
        /// `MSG_CONFIRM`.
        const CONFIRM = 0x800;
        /// `MSG_NOSIGNAL`.
        const NOSIGNAL = 0x4000;
        /// `MSG_MORE`.
        const MORE = 0x8000;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

bitflags! {
    /// Linux `MSG_*` flags accepted by [`recv`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct RecvFlags: u32 {
        /// `MSG_OOB`.
        const OOB = 0x1;
        /// `MSG_PEEK`.
        const PEEK = 0x2;
        /// `MSG_DONTWAIT`.
        const DONTWAIT = 0x40;
        /// `MSG_TRUNC`.
        const TRUNC = 0x20;
        /// `MSG_WAITALL`.
        const WAITALL = 0x100;
        /// `MSG_ERRQUEUE`.
        const ERRQUEUE = 0x2000;
        /// Wait for at least one message, then return as soon as the next
        /// message would block (`MSG_WAITFORONE`, used by `recvmmsg`).
        const WAITFORONE = 0x10000;
        /// `MSG_CMSG_CLOEXEC`.
        const CMSG_CLOEXEC = 0x4000_0000;
        /// Preserve future Linux-defined bits.
        const _ = !0;
    }
}

/// Creates two connected Linux sockets.
#[inline]
pub fn socketpair(
    domain: AddressFamily,
    type_: SocketType,
    flags: SocketFlags,
    protocol: Option<Protocol>,
) -> Result<(OwnedFd, OwnedFd)> {
    let protocol = protocol.map_or(0, |value| value.as_raw().get() as i32);
    let flags = checked_socket_flags(flags)?;
    let (first, second) =
        crabc_core::net::socketpair(domain.as_raw() as i32, type_.as_raw() | flags, protocol)?;
    // SAFETY: successful Linux `socketpair` returns two fresh, non-negative,
    // uniquely-owned descriptors.
    unsafe { Ok((OwnedFd::from_raw_fd(first), OwnedFd::from_raw_fd(second))) }
}

/// Creates one Linux socket and returns its unique owner.
///
/// `domain`, `type_`, and `protocol` are typed Linux socket values. `flags`
/// accepts only `SOCK_NONBLOCK` and `SOCK_CLOEXEC`; use
/// [`SocketFlags::from_bits`] when adapting a raw word so unsupported bits
/// are rejected before a syscall. `None` selects the domain's default
/// protocol, matching Rustix and the C `protocol = 0` convention.
#[inline]
pub fn socket(
    domain: AddressFamily,
    type_: SocketType,
    flags: SocketFlags,
    protocol: Option<Protocol>,
) -> Result<OwnedFd> {
    let protocol = protocol.map_or(0, |value| value.as_raw().get() as i32);
    let flags = checked_socket_flags(flags)?;
    let fd = crabc_core::net::socket(domain.as_raw() as i32, type_.as_raw() | flags, protocol)?;
    // SAFETY: successful Linux `socket` returns one fresh, non-negative,
    // uniquely-owned descriptor.
    unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
}

/// Sets Linux `SOL_SOCKET/SO_REUSEADDR` on a borrowed socket descriptor.
///
/// The option is represented as a Rust `bool`; Linux receives the required
/// four-byte integer encoding internally. The descriptor remains owned by the
/// caller, and kernel failures are returned as [`crate::Errno`] values without
/// consulting C `errno`.
#[inline]
pub fn set_socket_reuseaddr<Fd: AsFd>(fd: Fd, enabled: bool) -> Result<()> {
    crabc_core::net::set_socket_reuseaddr(fd.as_fd().as_raw_fd(), enabled)
}

/// Reads Linux `SOL_SOCKET/SO_REUSEADDR` from a borrowed socket descriptor.
///
/// A nonzero Linux option value is returned as `true`. The API is deliberately
/// specific to this supported option: callers cannot pass arbitrary option
/// levels, names, pointers, or lengths.
#[inline]
pub fn socket_reuseaddr<Fd: AsFd>(fd: Fd) -> Result<bool> {
    crabc_core::net::socket_reuseaddr(fd.as_fd().as_raw_fd())
}

/// Enables listening for incoming connections on a stream socket.
///
/// `backlog` is the signed Linux `listen(2)` backlog value. Linux applies its
/// own queue-size rules; this facade does not reinterpret or clamp it before
/// the direct syscall.
#[inline]
pub fn listen<Fd: AsFd>(fd: Fd, backlog: i32) -> Result<()> {
    crabc_core::net::listen(fd.as_fd().as_raw_fd(), backlog)
}

/// Accepts one pending connection without requesting a peer address.
///
/// The returned descriptor is uniquely owned. Linux's `accept(2)` semantics
/// are preserved: the accepted descriptor does not inherit `O_NONBLOCK` or
/// `FD_CLOEXEC` from the listener.
#[inline]
pub fn accept<Fd: AsFd>(fd: Fd) -> Result<OwnedFd> {
    // SAFETY: Null output pointers select the address-free Linux `accept`
    // form; the borrowed listener remains open for the syscall.
    let accepted = unsafe {
        crabc_core::net::accept_raw(
            fd.as_fd().as_raw_fd(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )?
    };
    // SAFETY: Linux returned a fresh, non-negative descriptor whose ownership
    // is transferred to this facade.
    unsafe { Ok(OwnedFd::from_raw_fd(accepted)) }
}

/// Accepts one pending connection through Linux `accept4(2)`.
///
/// `CLOEXEC` is applied atomically to the returned descriptor's descriptor
/// flags, and `NONBLOCK` is applied atomically to its file status flags. The
/// closed [`SocketFlags`] vocabulary rejects unknown bits with
/// [`crate::Errno::INVAL`], including values deliberately created with
/// `from_bits_retain`.
#[inline]
pub fn accept_with<Fd: AsFd>(fd: Fd, flags: SocketFlags) -> Result<OwnedFd> {
    let flags = checked_socket_flags(flags)?;
    // SAFETY: Null output pointers select the address-free Linux `accept4`
    // form; the borrowed listener remains open for the syscall.
    let accepted = unsafe {
        crabc_core::net::accept4_raw(
            fd.as_fd().as_raw_fd(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            flags,
        )?
    };
    // SAFETY: Linux returned a fresh, non-negative descriptor whose ownership
    // is transferred to this facade.
    unsafe { Ok(OwnedFd::from_raw_fd(accepted)) }
}

/// Alias for [`accept_with`], named after the Linux `accept4(2)` operation.
#[inline]
pub fn accept4<Fd: AsFd>(fd: Fd, flags: SocketFlags) -> Result<OwnedFd> {
    accept_with(fd, flags)
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

enum EncodedSocketAddress {
    V4(SockaddrIn),
    V6(SockaddrIn6),
}

impl EncodedSocketAddress {
    fn as_raw(&self) -> (*const u8, u32) {
        match self {
            Self::V4(address) => (
                (address as *const SockaddrIn).cast(),
                size_of::<SockaddrIn>() as u32,
            ),
            Self::V6(address) => (
                (address as *const SockaddrIn6).cast(),
                size_of::<SockaddrIn6>() as u32,
            ),
        }
    }
}

fn encode_socket_address(address: SocketAddress) -> Result<EncodedSocketAddress> {
    match address.ip() {
        IpAddress::V4(_) => {
            if address.scope_id() != 0 {
                return Err(crate::Errno::INVAL);
            }
            let octets = address.ip().octets();
            Ok(EncodedSocketAddress::V4(SockaddrIn {
                family: AddressFamily::INET.as_raw(),
                port: address.port().to_be(),
                address: u32::from_ne_bytes([octets[0], octets[1], octets[2], octets[3]]),
                zero: [0; 8],
            }))
        }
        IpAddress::V6(_) => Ok(EncodedSocketAddress::V6(SockaddrIn6 {
            family: AddressFamily::INET6.as_raw(),
            port: address.port().to_be(),
            flow_info: 0,
            address: address.ip().octets(),
            scope_id: address.scope_id(),
        })),
    }
}

#[repr(C, align(8))]
struct SockaddrStorage {
    bytes: [u8; 128],
}

fn read_u16_native(bytes: &[u8], offset: usize) -> u16 {
    // SAFETY: Callers validate that the returned sockaddr length covers this
    // field before reading it; unaligned access keeps the ABI helper explicit.
    unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(offset).cast()) }
}

fn read_u32_native(bytes: &[u8], offset: usize) -> u32 {
    // SAFETY: Callers validate that the returned sockaddr length covers this
    // field before reading it; unaligned access keeps the ABI helper explicit.
    unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(offset).cast()) }
}

fn decode_socket_address(storage: &SockaddrStorage, length: u32) -> Result<SocketAddress> {
    let length = length as usize;
    if length > size_of::<SockaddrStorage>() {
        return Err(crate::Errno::OVERFLOW);
    }
    if length < size_of::<u16>() {
        return Err(crate::Errno::INVAL);
    }
    let family = read_u16_native(&storage.bytes, 0);
    if family == AddressFamily::INET.as_raw() {
        if length < size_of::<SockaddrIn>() {
            return Err(crate::Errno::INVAL);
        }
        let address = read_u32_native(&storage.bytes, 4).to_ne_bytes();
        let port = u16::from_be(read_u16_native(&storage.bytes, 2));
        return Ok(SocketAddress::new(IpAddress::V4(address), port));
    }
    if family == AddressFamily::INET6.as_raw() {
        if length < size_of::<SockaddrIn6>() {
            return Err(crate::Errno::INVAL);
        }
        let mut address = [0u8; 16];
        address.copy_from_slice(&storage.bytes[8..24]);
        let port = u16::from_be(read_u16_native(&storage.bytes, 2));
        let scope_id = read_u32_native(&storage.bytes, 24);
        return Ok(SocketAddress::new_scoped(
            IpAddress::V6(address),
            port,
            scope_id,
        ));
    }
    Err(crate::Errno::AFNOSUPPORT)
}

/// Connects an existing socket to a caller-owned IPv4 or IPv6 endpoint.
///
/// The endpoint is encoded into an exact stack `sockaddr_in` or
/// `sockaddr_in6`: family is the native Linux `sa_family_t` representation,
/// while port and address bytes are in network order. The descriptor is only
/// borrowed for the syscall and remains owned by the caller.
///
/// IPv4 does not have a scope field. An IPv4 [`SocketAddress`] with a nonzero
/// scope is rejected with [`crate::Errno::INVAL`] before the syscall so that the
/// value cannot be silently lost. IPv6 scope identifiers are forwarded as
/// `sin6_scope_id`.
#[inline]
pub fn connect<Fd: AsFd>(fd: Fd, address: SocketAddress) -> Result<()> {
    let fd = fd.as_fd();
    let encoded = encode_socket_address(address)?;
    let (address, address_length) = encoded.as_raw();
    // SAFETY: `encoded` is the exact Linux/AArch64 sockaddr layout and remains
    // alive for the duration of the direct syscall.
    unsafe { crabc_core::net::connect_raw(fd.as_raw_fd(), address, address_length) }
}

/// Binds an existing socket to a caller-owned IPv4 or IPv6 endpoint.
///
/// The endpoint uses the same stack address encoding as [`connect`]. A port
/// of zero asks Linux to choose an ephemeral port; [`getsockname`] can then
/// retrieve the assigned endpoint. IPv4 scope identifiers are rejected with
/// [`crate::Errno::INVAL`] instead of being discarded.
#[inline]
pub fn bind<Fd: AsFd>(fd: Fd, address: SocketAddress) -> Result<()> {
    let fd = fd.as_fd();
    let encoded = encode_socket_address(address)?;
    let (address, address_length) = encoded.as_raw();
    // SAFETY: `encoded` is the exact Linux/AArch64 sockaddr layout and remains
    // alive for the duration of the direct syscall.
    unsafe { crabc_core::net::bind_raw(fd.as_raw_fd(), address, address_length) }
}

/// Accepts one pending connection and strictly decodes its IPv4 or IPv6 peer
/// address.
///
/// Linux may return any socket family through the raw `accept` address
/// pointer. This typed facade represents only IPv4 and IPv6, so unsupported
/// families return [`crate::Errno::AFNOSUPPORT`] rather than exposing an
/// opaque or partially initialized address. If decoding fails after the
/// kernel creates the connection, the new [`OwnedFd`] is dropped before the
/// error is returned.
#[inline]
pub fn acceptfrom<Fd: AsFd>(fd: Fd) -> Result<(OwnedFd, SocketAddress)> {
    acceptfrom_with_raw(fd, None)
}

/// Accepts one pending connection through `accept4(2)` and strictly decodes
/// its IPv4 or IPv6 peer address.
///
/// `CLOEXEC` and `NONBLOCK` have the same atomic descriptor and status-flag
/// semantics as [`accept_with`]. Unsupported peer families return
/// [`crate::Errno::AFNOSUPPORT`] and close the newly created descriptor.
#[inline]
pub fn acceptfrom_with<Fd: AsFd>(fd: Fd, flags: SocketFlags) -> Result<(OwnedFd, SocketAddress)> {
    let flags = checked_socket_flags(flags)?;
    acceptfrom_with_raw(fd, Some(flags))
}

fn acceptfrom_with_raw<Fd: AsFd>(fd: Fd, flags: Option<u32>) -> Result<(OwnedFd, SocketAddress)> {
    let mut storage = SockaddrStorage { bytes: [0; 128] };
    let mut length = size_of::<SockaddrStorage>() as u32;
    let accepted = match flags {
        // SAFETY: `storage` is writable for the full sockaddr_storage
        // capacity, and `length` is writable socklen_t storage for Linux to
        // replace with the initialized address length.
        None => unsafe {
            crabc_core::net::accept_raw(
                fd.as_fd().as_raw_fd(),
                storage.bytes.as_mut_ptr(),
                &mut length,
            )?
        },
        // SAFETY: The output storage contract is identical for accept4; the
        // typed flag word is forwarded to Linux's direct syscall boundary.
        Some(flags) => unsafe {
            crabc_core::net::accept4_raw(
                fd.as_fd().as_raw_fd(),
                storage.bytes.as_mut_ptr(),
                &mut length,
                flags,
            )?
        },
    };
    // SAFETY: Linux returned a fresh, non-negative descriptor whose ownership
    // is transferred to this facade. If the strict decoder below fails, drop
    // closes it before the error escapes.
    let accepted = unsafe { OwnedFd::from_raw_fd(accepted) };
    let address = decode_socket_address(&storage, length)?;
    Ok((accepted, address))
}

/// Returns the local IPv4 or IPv6 endpoint of an existing socket.
///
/// Linux returns a variable-length `sockaddr`; this facade validates the
/// returned length before decoding and returns [`crate::Errno::AFNOSUPPORT`]
/// for families other than INET and INET6 rather than interpreting unrelated
/// bytes as an IP endpoint.
#[inline]
pub fn getsockname<Fd: AsFd>(fd: Fd) -> Result<SocketAddress> {
    let fd = fd.as_fd();
    let mut storage = SockaddrStorage { bytes: [0; 128] };
    let mut length = size_of::<SockaddrStorage>() as u32;
    // SAFETY: `storage` provides aligned writable space for the Linux
    // sockaddr_storage capacity, and `length` is writable socklen_t storage.
    unsafe {
        crabc_core::net::getsockname_raw(fd.as_raw_fd(), storage.bytes.as_mut_ptr(), &mut length)?
    };
    decode_socket_address(&storage, length)
}

/// Returns the connected peer's IPv4 or IPv6 endpoint.
///
/// Linux returns a variable-length `sockaddr`; this facade validates the
/// returned length before decoding and returns [`crate::Errno::AFNOSUPPORT`]
/// for families other than INET and INET6 rather than interpreting unrelated
/// bytes as an IP endpoint. An unconnected socket preserves Linux's
/// [`crate::Errno::NOTCONN`] result.
#[inline]
pub fn getpeername<Fd: AsFd>(fd: Fd) -> Result<SocketAddress> {
    let fd = fd.as_fd();
    let mut storage = SockaddrStorage { bytes: [0; 128] };
    let mut length = size_of::<SockaddrStorage>() as u32;
    // SAFETY: `storage` provides aligned writable space for the Linux
    // sockaddr_storage capacity, and `length` is writable socklen_t storage.
    unsafe {
        crabc_core::net::getpeername_raw(fd.as_raw_fd(), storage.bytes.as_mut_ptr(), &mut length)?
    };
    decode_socket_address(&storage, length)
}

/// Disables one direction of a socket without public C ABI or TLS `errno`.
#[inline]
pub fn shutdown<Fd: AsFd>(fd: Fd, how: Shutdown) -> Result<()> {
    crabc_core::net::shutdown(fd.as_fd().as_raw_fd(), how.as_raw())
}

/// Sends bytes through a connected socket.
#[inline]
pub fn send<Fd: AsFd>(fd: Fd, buffer: &[u8], flags: SendFlags) -> Result<usize> {
    let fd = fd.as_fd();
    // SAFETY: `buffer` is readable for its exact length; a null destination
    // selects the connected-socket form of Linux `sendto`.
    unsafe {
        crabc_core::net::sendto_raw(
            fd.as_raw_fd(),
            buffer.as_ptr(),
            buffer.len(),
            flags.bits(),
            core::ptr::null(),
            0,
        )
    }
}

/// Sends one ordinary vectored message through a connected socket.
///
/// The borrowed [`IoSlice`] records are assembled into one Linux `msghdr`
/// inside the direct `crabc-core` seam. This bounded form intentionally has no
/// destination address or ancillary-control argument; use [`sendto`] for an
/// addressed datagram. The descriptor and every source segment remain valid
/// for the direct syscall, and Linux's short-send result is returned unchanged.
#[inline]
pub fn sendmsg<Fd: AsFd>(fd: Fd, buffers: &[IoSlice<'_>], flags: SendFlags) -> Result<usize> {
    let fd = fd.as_fd();
    let iovecs = if buffers.is_empty() {
        core::ptr::null()
    } else {
        buffers.as_ptr().cast::<crabc_core::io::Iovec>()
    };
    // SAFETY: `IoSlice` is `repr(transparent)` over a Linux iovec and each
    // value retains its borrowed immutable source slice for this call. An
    // empty vector uses the explicitly permitted null iovec pointer.
    unsafe { crabc_core::net::sendmsg_raw(fd.as_raw_fd(), iovecs, buffers.len(), flags.bits()) }
}

/// Sends several ordinary connected messages through Linux `sendmmsg`.
///
/// The records are private AArch64 `mmsghdr` values assembled by
/// [`MMsgHdr::new_send`]. Linux returns the number of records completed, not
/// an all-or-nothing status; every completed record's byte count remains
/// available through [`MMsgHdr::bytes`]. Thus a short count is a successful
/// partial batch and is never retried or converted through C `errno`.
#[inline]
pub fn sendmmsg<Fd: AsFd>(fd: Fd, messages: &mut [MMsgHdr<'_>], flags: SendFlags) -> Result<usize> {
    let count = u32::try_from(messages.len()).map_err(|_| crate::Errno::OVERFLOW)?;
    let records = if messages.is_empty() {
        core::ptr::null_mut()
    } else {
        messages.as_mut_ptr().cast::<u8>()
    };
    // SAFETY: Every record was built by `MMsgHdr::new_send`, so its nested
    // iovec and source-byte borrows remain valid for this direct syscall. The
    // wrappers are transparent over the exact private Linux record.
    unsafe { crabc_core::net::sendmmsg_raw(fd.as_fd().as_raw_fd(), records, count, flags.bits()) }
}

/// Sends one datagram to an IPv4 or IPv6 endpoint.
///
/// The endpoint is encoded with the same exact Linux `sockaddr_in` or
/// `sockaddr_in6` layout used by [`connect`] and [`bind`]. It is kept alive
/// across the direct `sendto(2)` syscall, and an IPv4 scope identifier is
/// rejected with [`crate::Errno::INVAL`] rather than being discarded.
#[inline]
pub fn sendto<Fd: AsFd>(
    fd: Fd,
    buffer: &[u8],
    flags: SendFlags,
    address: SocketAddress,
) -> Result<usize> {
    let fd = fd.as_fd();
    let encoded = encode_socket_address(address)?;
    let (address, address_length) = encoded.as_raw();
    // SAFETY: `buffer` is readable for its exact length. `encoded` is the
    // exact Linux/AArch64 sockaddr layout and stays alive for the syscall.
    unsafe {
        crabc_core::net::sendto_raw(
            fd.as_raw_fd(),
            buffer.as_ptr(),
            buffer.len(),
            flags.bits(),
            address,
            address_length,
        )
    }
}

/// Receives bytes from a connected socket.
///
/// The second result is the kernel byte count before any `MSG_TRUNC`
/// truncation; its first result follows the initialized-buffer contract.
#[inline]
#[allow(private_interfaces)]
pub fn recv<Fd: AsFd, Buf: Buffer<u8>>(
    fd: Fd,
    mut buffer: Buf,
    flags: RecvFlags,
) -> Result<(Buf::Output, usize)> {
    let fd = fd.as_fd();
    let (pointer, length) = buffer.parts_mut();
    // SAFETY: `Buffer` supplies writable storage for exactly `length` bytes;
    // null source-address pointers select the connected-socket form.
    let received = unsafe {
        crabc_core::net::recvfrom_raw(
            fd.as_raw_fd(),
            pointer,
            length,
            flags.bits(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )?
    };
    // SAFETY: At most `length` bytes were initialized even when `MSG_TRUNC`
    // reports a longer datagram length.
    unsafe { Ok((buffer.assume_init(min(length, received)), received)) }
}

/// Receives one ordinary vectored message through the direct Linux `recvmsg`
/// syscall.
///
/// The destination is a borrowed vector of [`MsgIoSliceMut`] records. Each
/// record may borrow initialized or `MaybeUninit` storage; the successful
/// [`RecvMsg`] result reports Linux's full byte count and returned message
/// flags, while [`RecvMsg::initialized_segments`] exposes only the bytes the
/// kernel actually initialized. No address or ancillary-control storage is
/// supplied by this bounded form. `MSG_TRUNC` therefore preserves a full
/// datagram count even when the returned initialized prefixes fill less than
/// the message.
#[inline]
pub fn recvmsg<'a, Fd: AsFd>(
    fd: Fd,
    buffers: &'a mut [MsgIoSliceMut<'a>],
    flags: RecvFlags,
) -> Result<RecvMsg<'a>> {
    let fd = fd.as_fd();
    let mut capacity = 0usize;
    for buffer in buffers.iter() {
        capacity = capacity
            .checked_add(buffer.iovec.iov_len)
            .ok_or(crate::Errno::OVERFLOW)?;
    }
    let iovecs = if buffers.is_empty() {
        core::ptr::null()
    } else {
        buffers.as_ptr().cast::<crabc_core::io::Iovec>()
    };
    // SAFETY: `MsgIoSliceMut` is `repr(transparent)` over a Linux iovec. Each
    // wrapper retains an exclusive borrow of a disjoint destination range;
    // the records and ranges remain valid for this direct syscall.
    let (bytes, message_flags) = unsafe {
        crabc_core::net::recvmsg_raw(fd.as_raw_fd(), iovecs, buffers.len(), flags.bits())?
    };
    Ok(RecvMsg {
        buffers,
        bytes,
        initialized: min(capacity, bytes),
        flags: RecvFlags::from_bits_retain(message_flags),
    })
}

/// Receives several ordinary messages through Linux `recvmmsg`.
///
/// `timeout` is a relative Linux [`crate::fs::Timespec`] and is copied back
/// by the kernel. Passing `None` selects the blocking form. Linux's returned
/// record count is preserved as a successful partial batch, and each
/// completed record retains its full byte count and message flags through
/// [`MMsgHdr::bytes`] and [`MMsgHdr::flags`]. Only initialized receive
/// prefixes may be read with [`MMsgHdr::initialized_segments`].
#[inline]
pub fn recvmmsg<Fd: AsFd>(
    fd: Fd,
    messages: &mut [MMsgHdr<'_>],
    flags: RecvFlags,
    timeout: Option<&mut crate::fs::Timespec>,
) -> Result<usize> {
    let count = u32::try_from(messages.len()).map_err(|_| crate::Errno::OVERFLOW)?;
    let records = if messages.is_empty() {
        core::ptr::null_mut()
    } else {
        messages.as_mut_ptr().cast::<u8>()
    };
    let timeout = timeout.map_or(core::ptr::null_mut(), |value| {
        (value as *mut crate::fs::Timespec).cast::<u8>()
    });
    // SAFETY: Every record was built by `MMsgHdr::new_recv`, so its nested
    // iovec and exclusive destination borrows remain valid for this direct
    // syscall. The optional timeout is mutable storage for Linux's relative
    // timespec update and remains live for the call.
    unsafe {
        crabc_core::net::recvmmsg_raw(
            fd.as_fd().as_raw_fd(),
            records,
            count,
            flags.bits(),
            timeout,
        )
    }
}

/// Queries whether a stream socket's receive cursor is at its urgent-data
/// mark through Linux's fixed `SIOCATMARK` ioctl.
///
/// The request code and four-byte output storage are private to this bounded
/// operation. No generic ioctl, C ABI, or TLS `errno` state crosses the native
/// boundary; Linux descriptor errors are returned directly.
#[inline]
pub fn sockatmark<Fd: AsFd>(fd: Fd) -> Result<bool> {
    const SIOCATMARK: u32 = 0x8905;
    let mut value = MaybeUninit::<i32>::uninit();
    // SAFETY: SIOCATMARK writes one Linux `int` to the provided storage; the
    // fixed request and descriptor establish the complete ioctl contract.
    unsafe {
        crabc_core::io::ioctl_raw(
            fd.as_fd().as_raw_fd(),
            SIOCATMARK,
            value.as_mut_ptr().cast::<u8>(),
        )?;
        // SAFETY: A successful SIOCATMARK ioctl initialized the four-byte
        // integer output according to Linux's request contract.
        Ok(value.assume_init() != 0)
    }
}

/// Receives one datagram and strictly decodes its IPv4 or IPv6 source.
///
/// The returned byte count is the kernel datagram length before any
/// `MSG_TRUNC` shortening, while the [`Buffer`] output marks only the prefix
/// actually initialized in caller storage. Source families outside
/// [`SocketAddress`] return [`crate::Errno::AFNOSUPPORT`] instead of exposing
/// an opaque or partially decoded address.
#[inline]
#[allow(private_interfaces)]
pub fn recvfrom<Fd: AsFd, Buf: Buffer<u8>>(
    fd: Fd,
    mut buffer: Buf,
    flags: RecvFlags,
) -> Result<(Buf::Output, usize, SocketAddress)> {
    let fd = fd.as_fd();
    let (pointer, length) = buffer.parts_mut();
    let mut storage = SockaddrStorage { bytes: [0; 128] };
    let mut address_length = size_of::<SockaddrStorage>() as u32;
    // SAFETY: `Buffer` supplies writable storage for exactly `length` bytes;
    // `storage` and `address_length` supply the full writable Linux source
    // address output contract.
    let received = unsafe {
        crabc_core::net::recvfrom_raw(
            fd.as_raw_fd(),
            pointer,
            length,
            flags.bits(),
            storage.bytes.as_mut_ptr(),
            &mut address_length,
        )?
    };
    let source = decode_socket_address(&storage, address_length)?;
    // SAFETY: At most `length` bytes were initialized even when `MSG_TRUNC`
    // reports a longer datagram length. Source decoding above cannot alter
    // the received payload storage.
    unsafe { Ok((buffer.assume_init(min(length, received)), received, source)) }
}

fn parse_ipv4(value: &[u8]) -> Option<[u8; 4]> {
    let mut result = [0u8; 4];
    let mut part = 0usize;
    let mut number = 0u16;
    let mut digits = 0usize;
    for &byte in value.iter().chain(core::iter::once(&b'.')) {
        if byte.is_ascii_digit() {
            number = number.checked_mul(10)?.checked_add((byte - b'0') as u16)?;
            if number > 255 {
                return None;
            }
            digits += 1;
        } else if byte == b'.' && digits != 0 && part < 4 {
            result[part] = number as u8;
            part += 1;
            number = 0;
            digits = 0;
        } else {
            return None;
        }
    }
    (part == 4).then_some(result)
}

fn parse_ipv6(value: &[u8]) -> Option<[u8; 16]> {
    if !value.contains(&b':') {
        return None;
    }
    let mut groups = [0u16; 8];
    if let Some(compression) = value.windows(2).position(|window| window == b"::") {
        // A second `::` is ambiguous and therefore rejected. The two sides
        // are parsed independently, then the omitted groups are inserted in
        // the middle (including the legal leading/trailing `::` forms).
        if value[compression + 2..]
            .windows(2)
            .any(|window| window == b"::")
        {
            return None;
        }
        let left = parse_ipv6_side(&value[..compression], &mut groups, 0)?;
        let mut right_groups = [0u16; 8];
        let right = parse_ipv6_side(&value[compression + 2..], &mut right_groups, 0)?;
        if left + right >= 8 {
            return None;
        }
        for index in (0..right).rev() {
            groups[8 - right + index] = right_groups[index];
        }
    } else if parse_ipv6_side(value, &mut groups, 0)? != 8 {
        return None;
    }
    let mut result = [0u8; 16];
    for (index, group) in groups.into_iter().enumerate() {
        result[index * 2..index * 2 + 2].copy_from_slice(&group.to_be_bytes());
    }
    Some(result)
}

fn parse_ipv6_side(value: &[u8], groups: &mut [u16; 8], mut count: usize) -> Option<usize> {
    if value.is_empty() {
        return Some(count);
    }
    for (index, token) in value.split(|&byte| byte == b':').enumerate() {
        if token.is_empty() {
            return None;
        }
        if token.contains(&b'.') {
            if index + 1 != value.split(|&byte| byte == b':').count() {
                return None;
            }
            let ipv4 = parse_ipv4(token)?;
            if count + 2 > 8 {
                return None;
            }
            groups[count] = u16::from_be_bytes([ipv4[0], ipv4[1]]);
            groups[count + 1] = u16::from_be_bytes([ipv4[2], ipv4[3]]);
            count += 2;
        } else {
            if count >= 8 {
                return None;
            }
            groups[count] = parse_hex(token)?;
            count += 1;
        }
    }
    Some(count)
}

fn parse_hex(value: &[u8]) -> Option<u16> {
    if value.is_empty() || value.len() > 4 {
        return None;
    }
    let mut result = 0u16;
    for &byte in value {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        result = (result << 4) | digit as u16;
    }
    Some(result)
}

fn fmt_ipv6(formatter: &mut fmt::Formatter<'_>, bytes: [u8; 16]) -> fmt::Result {
    let mut groups = [0u16; 8];
    for index in 0..8 {
        groups[index] = u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    }
    let mut best_start = 8usize;
    let mut best_len = 0usize;
    let mut index = 0usize;
    while index < 8 {
        if groups[index] == 0 {
            let start = index;
            while index < 8 && groups[index] == 0 {
                index += 1;
            }
            if index - start > best_len {
                best_start = start;
                best_len = index - start;
            }
        } else {
            index += 1;
        }
    }
    if best_len < 2 {
        best_start = 8;
    }
    let mut index = 0usize;
    let mut separator_before_group = false;
    while index < 8 {
        if index == best_start {
            // The compression marker includes both separators needed after a
            // preceding group and before a following group. In particular,
            // leave the next group separator-free for `::1`, not `:::1`.
            formatter.write_str("::")?;
            index += best_len;
            separator_before_group = false;
            if index == 8 {
                break;
            }
        } else {
            if separator_before_group {
                formatter.write_str(":")?;
            }
            write!(formatter, "{:x}", groups[index])?;
            separator_before_group = true;
            index += 1;
        }
    }
    Ok(())
}
