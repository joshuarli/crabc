//! Darwin sockets, socket addresses and messages over libSystem.
//!
//! The raw functions have the names and shapes of the `crabc-core` network
//! seam, so the facade module keeps one body for the operations both targets
//! share. Darwin has no `SOCK_CLOEXEC`, `SOCK_NONBLOCK` or `accept4`: the
//! descriptor constructors here create the socket first and then set the
//! requested flags with `fcntl`.

use core::ffi::{c_int, c_void};
use core::mem::size_of;

use super::errno::{self, Errno, Result};
use super::sys;
use crate::net::{IpAddress, RawAddressFamily, SocketAddress};
use crate::{AsFd, BorrowedFd, OwnedFd, RawFd};

pub(crate) use sys::SockaddrStorage;

/// Darwin `AF_*` values used by socket constructors.
///
/// Darwin's `sa_family_t` is one byte; the facade keeps the 16-bit
/// [`RawAddressFamily`] so both targets share one signature.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AddressFamily(RawAddressFamily);

impl AddressFamily {
    /// `AF_UNSPEC`.
    pub const UNSPEC: Self = Self(sys::AF_UNSPEC as RawAddressFamily);
    /// `AF_UNIX`, also known as `AF_LOCAL`.
    pub const UNIX: Self = Self(sys::AF_UNIX as RawAddressFamily);
    /// `AF_INET`.
    pub const INET: Self = Self(sys::AF_INET as RawAddressFamily);
    /// `AF_INET6`, which is 30 on Darwin.
    pub const INET6: Self = Self(sys::AF_INET6 as RawAddressFamily);

    /// Constructs an address family from its Darwin value.
    #[inline]
    pub const fn from_raw(raw: RawAddressFamily) -> Self {
        Self(raw)
    }

    /// Returns the Darwin value.
    #[inline]
    pub const fn as_raw(self) -> RawAddressFamily {
        self.0
    }
}

bitflags::bitflags! {
    /// Descriptor flags requested from [`socket`], [`socketpair`] and the
    /// `accept` family.
    ///
    /// Darwin has no `SOCK_CLOEXEC` or `SOCK_NONBLOCK`, so these bits are not
    /// passed to libSystem: each constructor creates the descriptor and then
    /// sets `FD_CLOEXEC` and `O_NONBLOCK` with `fcntl`. The flag values are
    /// Darwin's `O_CLOEXEC` and `O_NONBLOCK`. The set is closed; unknown bits
    /// are rejected with [`Errno::INVAL`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SocketFlags: u32 {
        /// Set `O_NONBLOCK` on the new descriptor.
        const NONBLOCK = sys::O_NONBLOCK.cast_unsigned();
        /// Set `FD_CLOEXEC` on the new descriptor.
        ///
        /// This is not atomic: a `fork` on another thread between creation
        /// and the `fcntl` call gives the child a copy without
        /// close-on-exec, which then survives that child's `exec`.
        const CLOEXEC = sys::O_CLOEXEC.cast_unsigned();
    }
}

bitflags::bitflags! {
    /// Darwin `MSG_*` flags accepted by [`send`](crate::net::send).
    ///
    /// Linux's `CONFIRM` and `MORE` have no Darwin counterpart.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SendFlags: u32 {
        /// `MSG_OOB`.
        const OOB = sys::MSG_OOB.cast_unsigned();
        /// `MSG_DONTROUTE`.
        const DONTROUTE = sys::MSG_DONTROUTE.cast_unsigned();
        /// `MSG_DONTWAIT`.
        const DONTWAIT = sys::MSG_DONTWAIT.cast_unsigned();
        /// `MSG_EOR`.
        const EOR = sys::MSG_EOR.cast_unsigned();
        /// `MSG_NOSIGNAL`.
        const NOSIGNAL = sys::MSG_NOSIGNAL.cast_unsigned();
        /// Preserve unknown bits for libSystem validation.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// Darwin `MSG_*` flags accepted by [`recv`](crate::net::recv) and
    /// reported by [`recvmsg`](crate::net::recvmsg).
    ///
    /// Darwin reports `TRUNC` and `CTRUNC` only as output flags; requesting
    /// `TRUNC` does not change what a receive copies or returns. Linux's
    /// `ERRQUEUE`, `WAITFORONE` and `CMSG_CLOEXEC` do not exist.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct RecvFlags: u32 {
        /// `MSG_OOB`.
        const OOB = sys::MSG_OOB.cast_unsigned();
        /// `MSG_PEEK`.
        const PEEK = sys::MSG_PEEK.cast_unsigned();
        /// `MSG_DONTWAIT`.
        const DONTWAIT = sys::MSG_DONTWAIT.cast_unsigned();
        /// `MSG_TRUNC`: a datagram was longer than the supplied storage.
        const TRUNC = sys::MSG_TRUNC.cast_unsigned();
        /// `MSG_CTRUNC`: ancillary data was discarded.
        const CTRUNC = sys::MSG_CTRUNC.cast_unsigned();
        /// `MSG_WAITALL`.
        const WAITALL = sys::MSG_WAITALL.cast_unsigned();
        /// Preserve unknown bits for libSystem validation.
        const _ = !0;
    }
}

#[inline]
fn set_int_option(socket: RawFd, name: c_int, value: c_int) -> Result<()> {
    // SAFETY: `value` is a live `int` whose exact size is passed.
    let result = unsafe {
        sys::setsockopt(
            socket,
            sys::SOL_SOCKET,
            name,
            (&value as *const c_int).cast::<c_void>(),
            size_of::<c_int>() as sys::socklen_t,
        )
    };
    errno::check(result).map(|_| ())
}

#[inline]
fn int_option(socket: RawFd, name: c_int) -> Result<c_int> {
    let mut value: c_int = 0;
    let mut length = size_of::<c_int>() as sys::socklen_t;
    // SAFETY: `value` and `length` are live, writable and describe each
    // other for the call.
    let result = unsafe {
        sys::getsockopt(
            socket,
            sys::SOL_SOCKET,
            name,
            (&mut value as *mut c_int).cast::<c_void>(),
            &mut length,
        )
    };
    errno::check(result)?;
    if length as usize != size_of::<c_int>() {
        return Err(Errno::IO);
    }
    Ok(value)
}

/// `SO_REUSEADDR` as a boolean option.
#[inline]
pub(crate) fn set_socket_reuseaddr(socket: RawFd, enabled: bool) -> Result<()> {
    set_int_option(socket, sys::SO_REUSEADDR, c_int::from(enabled))
}

#[inline]
pub(crate) fn socket_reuseaddr(socket: RawFd) -> Result<bool> {
    int_option(socket, sys::SO_REUSEADDR).map(|value| value != 0)
}

#[inline]
pub(crate) fn set_socket_broadcast(socket: RawFd, enabled: bool) -> Result<()> {
    set_int_option(socket, sys::SO_BROADCAST, c_int::from(enabled))
}

#[inline]
pub(crate) fn socket_broadcast(socket: RawFd) -> Result<bool> {
    int_option(socket, sys::SO_BROADCAST).map(|value| value != 0)
}

#[inline]
pub(crate) fn set_socket_oobinline(socket: RawFd, enabled: bool) -> Result<()> {
    set_int_option(socket, sys::SO_OOBINLINE, c_int::from(enabled))
}

#[inline]
pub(crate) fn socket_oobinline(socket: RawFd) -> Result<bool> {
    int_option(socket, sys::SO_OOBINLINE).map(|value| value != 0)
}

#[inline]
pub(crate) fn socket_type(socket: RawFd) -> Result<u32> {
    int_option(socket, sys::SO_TYPE).map(c_int::cast_unsigned)
}

#[inline]
pub(crate) fn listen(socket: RawFd, backlog: i32) -> Result<()> {
    // SAFETY: `listen` has no memory arguments.
    errno::check(unsafe { sys::listen(socket, backlog) }).map(|_| ())
}

#[inline]
pub(crate) fn shutdown(socket: RawFd, how: i32) -> Result<()> {
    // SAFETY: `shutdown` has no memory arguments.
    errno::check(unsafe { sys::shutdown(socket, how) }).map(|_| ())
}

/// # Safety
///
/// `address` must be readable for `address_length` bytes.
#[inline]
pub(crate) unsafe fn connect_raw(socket: RawFd, address: *const u8, address_length: u32) -> Result<()> {
    // SAFETY: the caller supplies a readable address of the stated length.
    errno::check(unsafe { sys::connect(socket, address, address_length) }).map(|_| ())
}

/// # Safety
///
/// `address` must be readable for `address_length` bytes.
#[inline]
pub(crate) unsafe fn bind_raw(socket: RawFd, address: *const u8, address_length: u32) -> Result<()> {
    // SAFETY: the caller supplies a readable address of the stated length.
    errno::check(unsafe { sys::bind(socket, address, address_length) }).map(|_| ())
}

/// # Safety
///
/// `address` must be writable for `*address_length` bytes, and
/// `address_length` must be writable.
#[inline]
pub(crate) unsafe fn getsockname_raw(
    socket: RawFd,
    address: *mut u8,
    address_length: *mut u32,
) -> Result<()> {
    // SAFETY: the caller supplies writable address and length storage.
    errno::check(unsafe { sys::getsockname(socket, address, address_length) }).map(|_| ())
}

/// # Safety
///
/// As for [`getsockname_raw`].
#[inline]
pub(crate) unsafe fn getpeername_raw(
    socket: RawFd,
    address: *mut u8,
    address_length: *mut u32,
) -> Result<()> {
    // SAFETY: the caller supplies writable address and length storage.
    errno::check(unsafe { sys::getpeername(socket, address, address_length) }).map(|_| ())
}

/// # Safety
///
/// `buffer` must be readable for `length` bytes, and `address` null or
/// readable for `address_length` bytes.
#[inline]
pub(crate) unsafe fn sendto_raw(
    socket: RawFd,
    buffer: *const u8,
    length: usize,
    flags: u32,
    address: *const u8,
    address_length: u32,
) -> Result<usize> {
    // SAFETY: the caller supplies the readable payload and optional address.
    let sent = unsafe {
        sys::sendto(socket, buffer.cast(), length, flags.cast_signed(), address, address_length)
    };
    errno::check_size(sent)
}

/// # Safety
///
/// `buffer` must be writable for `length` bytes, and `address` and
/// `address_length` both null or writable as for [`getsockname_raw`].
#[inline]
pub(crate) unsafe fn recvfrom_raw(
    socket: RawFd,
    buffer: *mut u8,
    length: usize,
    flags: u32,
    address: *mut u8,
    address_length: *mut u32,
) -> Result<usize> {
    // SAFETY: the caller supplies the writable payload and optional address.
    let received = unsafe {
        sys::recvfrom(socket, buffer.cast(), length, flags.cast_signed(), address, address_length)
    };
    errno::check_size(received)
}

/// Builds an address-free, control-free `msghdr` over `count` iovecs.
///
/// XNU rejects a segment count of zero or above `UIO_MAXIOV` with
/// `EMSGSIZE`; a count beyond `int` is reported the same way here.
#[inline]
fn message_header(iovecs: *const sys::Iovec, count: usize) -> Result<sys::Msghdr> {
    let count = c_int::try_from(count).map_err(|_| Errno::MSGSIZE)?;
    Ok(sys::Msghdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: iovecs.cast_mut(),
        msg_iovlen: count,
        msg_control: core::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    })
}

/// # Safety
///
/// `iovecs` must be null or point to `count` initialized iovecs whose
/// ranges are readable for the call.
#[inline]
pub(crate) unsafe fn sendmsg_raw(
    socket: RawFd,
    iovecs: *const sys::Iovec,
    count: usize,
    flags: u32,
) -> Result<usize> {
    let header = message_header(iovecs, count)?;
    // SAFETY: `header` is live for the call and the caller supplies its
    // iovec array; libSystem only reads the payload.
    errno::check_size(unsafe { sys::sendmsg(socket, &header, flags.cast_signed()) })
}

/// Returns the byte count and the returned `msg_flags`.
///
/// # Safety
///
/// `iovecs` must be null or point to `count` initialized iovecs whose
/// ranges are writable for the call.
#[inline]
pub(crate) unsafe fn recvmsg_raw(
    socket: RawFd,
    iovecs: *const sys::Iovec,
    count: usize,
    flags: u32,
) -> Result<(usize, u32)> {
    let mut header = message_header(iovecs, count)?;
    // SAFETY: `header` is live and writable for the call and the caller
    // supplies writable destination ranges.
    let bytes = errno::check_size(unsafe { sys::recvmsg(socket, &mut header, flags.cast_signed()) })?;
    Ok((bytes, header.msg_flags.cast_unsigned()))
}

/// XNU never discards a receive's payload for `MSG_TRUNC`, so every received
/// byte up to the buffer capacity is initialized.
#[inline]
pub(crate) fn receive_payload_discarded(_fd: BorrowedFd<'_>, _flags: RecvFlags) -> Result<bool> {
    Ok(false)
}

/// Applies the requested [`SocketFlags`] to a socket that was just created,
/// in place of the atomic Linux flags. A new socket has neither flag, so only
/// requested flags need a call.
#[inline]
fn apply_socket_flags(fd: &OwnedFd, flags: SocketFlags) -> Result<()> {
    if flags.contains(SocketFlags::CLOEXEC) {
        set_close_on_exec(fd.as_raw_fd())?;
    }
    if flags.contains(SocketFlags::NONBLOCK) {
        set_nonblocking(fd.as_raw_fd(), true)?;
    }
    Ok(())
}

/// Sets `FD_CLOEXEC`.
#[inline]
fn set_close_on_exec(fd: RawFd) -> Result<()> {
    // SAFETY: `F_SETFD` takes one `int` argument and no pointer.
    errno::check(unsafe { sys::fcntl(fd, sys::F_SETFD, sys::FD_CLOEXEC) }).map(|_| ())
}

/// Sets or clears `O_NONBLOCK`, leaving the other status flags unchanged.
#[inline]
fn set_nonblocking(fd: RawFd, enabled: bool) -> Result<()> {
    // SAFETY: `F_GETFL` takes no argument.
    let status = errno::check(unsafe { sys::fcntl(fd, sys::F_GETFL) })?;
    let wanted = if enabled {
        status | sys::O_NONBLOCK
    } else {
        status & !sys::O_NONBLOCK
    };
    if wanted == status {
        return Ok(());
    }
    // SAFETY: `F_SETFL` takes one `int` argument and no pointer.
    errno::check(unsafe { sys::fcntl(fd, sys::F_SETFL, wanted) }).map(|_| ())
}

#[inline]
fn checked_socket_flags(flags: SocketFlags) -> Result<SocketFlags> {
    SocketFlags::from_bits(flags.bits()).ok_or(Errno::INVAL)
}

/// Creates one socket and returns its unique owner.
///
/// `flags` accepts only [`SocketFlags::NONBLOCK`] and
/// [`SocketFlags::CLOEXEC`], which are set with `fcntl` after creation;
/// unknown bits fail with [`Errno::INVAL`] before the call. `None` selects
/// the domain's default protocol.
///
/// `CLOEXEC` is not atomic here: a `fork` on another thread between
/// `socket` and the `fcntl` call can give its child a copy of the socket
/// without close-on-exec, which then survives that child's `exec`.
#[inline]
pub fn socket(
    domain: AddressFamily,
    type_: crate::net::SocketType,
    flags: SocketFlags,
    protocol: Option<crate::net::Protocol>,
) -> Result<OwnedFd> {
    let flags = checked_socket_flags(flags)?;
    let protocol = protocol.map_or(0, |value| value.as_raw().get() as c_int);
    let fd = errno::check(sys::socket(
        c_int::from(domain.as_raw()),
        type_.as_raw() as c_int,
        protocol,
    ))?;
    // SAFETY: a successful `socket` returns a new descriptor whose
    // ownership transfers here; it is closed if applying the flags fails.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    apply_socket_flags(&fd, flags)?;
    Ok(fd)
}

/// Creates two connected sockets.
///
/// The flags are applied to both descriptors with `fcntl` after creation,
/// with the same non-atomic `CLOEXEC` as [`socket`].
#[inline]
pub fn socketpair(
    domain: AddressFamily,
    type_: crate::net::SocketType,
    flags: SocketFlags,
    protocol: Option<crate::net::Protocol>,
) -> Result<(OwnedFd, OwnedFd)> {
    let flags = checked_socket_flags(flags)?;
    let protocol = protocol.map_or(0, |value| value.as_raw().get() as c_int);
    let mut fds: [c_int; 2] = [-1, -1];
    // SAFETY: `fds` is writable storage for the two descriptors.
    let result = unsafe {
        sys::socketpair(
            c_int::from(domain.as_raw()),
            type_.as_raw() as c_int,
            protocol,
            fds.as_mut_ptr(),
        )
    };
    errno::check(result)?;
    // SAFETY: a successful `socketpair` stored two new descriptors; each
    // owner closes its end if applying the flags fails.
    let first = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: as above, for the second end.
    let second = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    apply_socket_flags(&first, flags)?;
    apply_socket_flags(&second, flags)?;
    Ok((first, second))
}

/// Accepts one connection, optionally decoding the peer address, and sets
/// the requested descriptor flags.
///
/// XNU copies the listener's `O_NONBLOCK` to the accepted socket. The flags
/// are applied afterwards, so the accepted descriptor is nonblocking exactly
/// when `NONBLOCK` is requested, as with Linux `accept4`.
fn accept_with_address<Fd: AsFd>(
    fd: Fd,
    flags: SocketFlags,
    storage: Option<&mut (SockaddrStorage, u32)>,
) -> Result<OwnedFd> {
    let (address, length) = match storage {
        Some((storage, length)) => (storage.bytes.as_mut_ptr(), length as *mut u32),
        None => (core::ptr::null_mut(), core::ptr::null_mut()),
    };
    // SAFETY: the address and length pointers are both null, or point to
    // writable storage whose capacity `*length` describes.
    let accepted = unsafe { sys::accept(fd.as_fd().as_raw_fd(), address, length) };
    let accepted = errno::check(accepted)?;
    // SAFETY: a successful `accept` returns a new descriptor whose ownership
    // transfers here; it is closed if applying the flags fails.
    let accepted = unsafe { OwnedFd::from_raw_fd(accepted) };
    if flags.contains(SocketFlags::CLOEXEC) {
        set_close_on_exec(accepted.as_raw_fd())?;
    }
    set_nonblocking(accepted.as_raw_fd(), flags.contains(SocketFlags::NONBLOCK))?;
    Ok(accepted)
}

/// Accepts one pending connection without requesting a peer address.
///
/// The accepted descriptor has neither close-on-exec nor `O_NONBLOCK`, as on
/// Linux: XNU's inherited `O_NONBLOCK` is cleared.
#[inline]
pub fn accept<Fd: AsFd>(fd: Fd) -> Result<OwnedFd> {
    accept_with_address(fd, SocketFlags::empty(), None)
}

/// Accepts one pending connection and sets the requested descriptor flags.
///
/// Unknown bits fail with [`Errno::INVAL`] before the call. Darwin has no
/// `accept4`, so `CLOEXEC` is set after `accept` returns and has the fork
/// race described for [`socket`].
#[inline]
pub fn accept_with<Fd: AsFd>(fd: Fd, flags: SocketFlags) -> Result<OwnedFd> {
    let flags = checked_socket_flags(flags)?;
    accept_with_address(fd, flags, None)
}

/// Accepts one pending connection and strictly decodes its IPv4 or IPv6 peer.
///
/// Other peer families return [`Errno::AFNOSUPPORT`] after closing the new
/// descriptor.
#[inline]
pub fn acceptfrom<Fd: AsFd>(fd: Fd) -> Result<(OwnedFd, SocketAddress)> {
    let mut storage = (SockaddrStorage { bytes: [0; 128] }, size_of::<SockaddrStorage>() as u32);
    let accepted = accept_with_address(fd, SocketFlags::empty(), Some(&mut storage))?;
    let address = decode_socket_address(&storage.0, storage.1)?;
    Ok((accepted, address))
}

/// Accepts one pending connection with the requested descriptor flags and
/// strictly decodes its IPv4 or IPv6 peer.
///
/// `CLOEXEC` has the fork race described for [`socket`].
#[inline]
pub fn acceptfrom_with<Fd: AsFd>(fd: Fd, flags: SocketFlags) -> Result<(OwnedFd, SocketAddress)> {
    let flags = checked_socket_flags(flags)?;
    let mut storage = (SockaddrStorage { bytes: [0; 128] }, size_of::<SockaddrStorage>() as u32);
    let accepted = accept_with_address(fd, flags, Some(&mut storage))?;
    let address = decode_socket_address(&storage.0, storage.1)?;
    Ok((accepted, address))
}

/// Reports whether a stream socket's receive cursor is at its urgent-data
/// mark, through libSystem `sockatmark`.
#[inline]
pub fn sockatmark<Fd: AsFd>(fd: Fd) -> Result<bool> {
    // SAFETY: `sockatmark` has no memory arguments.
    let result = unsafe { sys::sockatmark(fd.as_fd().as_raw_fd()) };
    errno::check(result).map(|value| value != 0)
}

/// An IPv4 or IPv6 endpoint encoded as a Darwin `sockaddr`, with `sin_len`
/// set.
pub(crate) enum EncodedSocketAddress {
    V4(sys::SockaddrIn),
    V6(sys::SockaddrIn6),
}

impl EncodedSocketAddress {
    pub(crate) fn as_raw(&self) -> (*const u8, u32) {
        match self {
            Self::V4(address) => (
                (address as *const sys::SockaddrIn).cast(),
                size_of::<sys::SockaddrIn>() as u32,
            ),
            Self::V6(address) => (
                (address as *const sys::SockaddrIn6).cast(),
                size_of::<sys::SockaddrIn6>() as u32,
            ),
        }
    }
}

/// Encodes `address`; an IPv4 endpoint with a nonzero scope is rejected with
/// [`Errno::INVAL`] rather than losing the scope.
pub(crate) fn encode_socket_address(address: SocketAddress) -> Result<EncodedSocketAddress> {
    match address.ip() {
        IpAddress::V4(octets) => {
            if address.scope_id() != 0 {
                return Err(Errno::INVAL);
            }
            Ok(EncodedSocketAddress::V4(sys::SockaddrIn {
                sin_len: size_of::<sys::SockaddrIn>() as u8,
                sin_family: sys::AF_INET as u8,
                sin_port: address.port().to_be(),
                sin_addr: u32::from_ne_bytes(octets),
                sin_zero: [0; 8],
            }))
        }
        IpAddress::V6(octets) => Ok(EncodedSocketAddress::V6(sys::SockaddrIn6 {
            sin6_len: size_of::<sys::SockaddrIn6>() as u8,
            sin6_family: sys::AF_INET6 as u8,
            sin6_port: address.port().to_be(),
            sin6_flowinfo: 0,
            sin6_addr: octets,
            sin6_scope_id: address.scope_id(),
        })),
    }
}

#[inline]
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([bytes[offset], bytes[offset + 1]])
}

#[inline]
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

/// Strictly decodes the IPv4 or IPv6 `sockaddr` that libSystem returned.
///
/// The family byte follows Darwin's one-byte `sa_len`. A length beyond the
/// storage is [`Errno::OVERFLOW`], a short record [`Errno::INVAL`], and any
/// other family [`Errno::AFNOSUPPORT`].
pub(crate) fn decode_socket_address(storage: &SockaddrStorage, length: u32) -> Result<SocketAddress> {
    let length = length as usize;
    if length > size_of::<SockaddrStorage>() {
        return Err(Errno::OVERFLOW);
    }
    if length < 2 {
        return Err(Errno::INVAL);
    }
    let bytes = &storage.bytes;
    match c_int::from(bytes[1]) {
        sys::AF_INET => {
            if length < size_of::<sys::SockaddrIn>() {
                return Err(Errno::INVAL);
            }
            let port = u16::from_be(read_u16(bytes, 2));
            let address = [bytes[4], bytes[5], bytes[6], bytes[7]];
            Ok(SocketAddress::new(IpAddress::V4(address), port))
        }
        sys::AF_INET6 => {
            if length < size_of::<sys::SockaddrIn6>() {
                return Err(Errno::INVAL);
            }
            let port = u16::from_be(read_u16(bytes, 2));
            let mut address = [0u8; 16];
            address.copy_from_slice(&bytes[8..24]);
            let scope_id = read_u32(bytes, 24);
            Ok(SocketAddress::new_scoped(IpAddress::V6(address), port, scope_id))
        }
        _ => Err(Errno::AFNOSUPPORT),
    }
}
