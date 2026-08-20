//! Direct Linux socket-pair operations.
//!
//! The first networking slice deliberately starts with local connected socket
//! pairs. It provides descriptor ownership and buffer semantics without
//! coupling native Rust code to libc's resolver or process-global state.

use bitflags::bitflags;
use core::cmp::min;
use core::num::NonZeroU32;

use crate::buffer::Buffer;
use crate::{AsFd, OwnedFd, Result};

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

/// A raw, non-default Linux protocol number.
pub type RawProtocol = NonZeroU32;

/// A non-default Linux socket protocol.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Protocol(RawProtocol);

impl Protocol {
    /// Constructs a protocol from a nonzero Linux ABI value.
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
    /// Socket creation flags accepted by Linux `socketpair`.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SocketFlags: u32 {
        /// `SOCK_NONBLOCK`.
        const NONBLOCK = 0x0000_0800;
        /// `SOCK_CLOEXEC`.
        const CLOEXEC = 0x0008_0000;
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
    let (first, second) = crabc_core::net::socketpair(
        domain.as_raw() as i32,
        type_.as_raw() | flags.bits(),
        protocol,
    )?;
    // SAFETY: successful Linux `socketpair` returns two fresh, non-negative,
    // uniquely-owned descriptors.
    unsafe { Ok((OwnedFd::from_raw_fd(first), OwnedFd::from_raw_fd(second))) }
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
