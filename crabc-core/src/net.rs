//! Stateless Linux LP64 socket operations.

use core::mem::MaybeUninit;

use crate::{RawFd, Result};
use crate::syscall::{decode, decode_i32, syscall2, syscall3, syscall4, syscall5, syscall6, SYS_ACCEPT, SYS_ACCEPT4, SYS_BIND, SYS_CONNECT, SYS_GETPEERNAME, SYS_GETSOCKNAME, SYS_GETSOCKOPT, SYS_LISTEN, SYS_RECVFROM, SYS_RECVMMSG, SYS_RECVMSG, SYS_SENDMMSG, SYS_SENDMSG, SYS_SENDTO, SYS_SETSOCKOPT, SYS_SHUTDOWN, SYS_SOCKET, SYS_SOCKETPAIR};

use crate::io::Iovec;

const SOL_SOCKET: usize = 1;
const SO_REUSEADDR: usize = 2;
const SO_BROADCAST: usize = 6;
const SO_OOBINLINE: usize = 10;
const SO_TYPE: usize = 3;
const SO_ERROR: usize = 4;
const SO_PROTOCOL: usize = 38;
const SO_DOMAIN: usize = 39;
const SO_ACCEPTCONN: usize = 30;
const SO_COOKIE: usize = 57;

/// Creates a Linux socket without libc or TLS `errno`.
#[inline]
pub fn socket(domain: i32, type_and_flags: u32, protocol: i32) -> Result<RawFd> {
    // SAFETY: Linux validates these scalar socket parameters.
    decode_i32(unsafe {
        crate::syscall::syscall3(
            SYS_SOCKET,
            domain as usize,
            type_and_flags as usize,
            protocol as usize,
        )
    })
}

/// Sets Linux `SOL_SOCKET/SO_REUSEADDR` without libc or TLS `errno`.
///
/// Linux represents this boolean socket option as a four-byte integer.
/// The value is kept entirely inside this typed seam; callers cannot
/// provide an arbitrary option level, name, pointer, or length.
#[inline]
pub fn set_socket_reuseaddr(socket: RawFd, enabled: bool) -> Result<()> {
    let value = u32::from(enabled);
    // SAFETY: `value` is a live four-byte integer for the duration of the
    // direct syscall, and Linux validates the descriptor and option.
    decode(unsafe {
        syscall5(
            SYS_SETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_REUSEADDR,
            (&value as *const u32) as usize,
            core::mem::size_of::<u32>(),
        )
    })
    .map(|_| ())
}

/// Gets Linux `SOL_SOCKET/SO_REUSEADDR` without libc or TLS `errno`.
///
/// Linux returns this boolean socket option as a four-byte integer. A
/// nonzero value is `true`, matching Rustix and the Linux socket ABI.
#[inline]
pub fn socket_reuseaddr(socket: RawFd) -> Result<bool> {
    let mut value = MaybeUninit::<u32>::uninit();
    let mut length = core::mem::size_of::<u32>() as u32;
    // SAFETY: `value` and `length` are writable Linux socket-option output
    // storage for the duration of the direct syscall.
    decode(unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_REUSEADDR,
            value.as_mut_ptr() as usize,
            (&mut length as *mut u32) as usize,
        )
    })?;
    if length as usize != core::mem::size_of::<u32>() {
        return Err(crate::Errno::INVAL);
    }
    // SAFETY: Linux initialized exactly the four bytes described by
    // `length` on successful `getsockopt`.
    Ok(unsafe { value.assume_init() } != 0)
}

/// Sets Linux `SOL_SOCKET/SO_BROADCAST` without libc or TLS `errno`.
///
/// Linux represents this boolean socket option as a four-byte integer.
/// The value is kept entirely inside this typed seam; callers cannot
/// provide an arbitrary option level, name, pointer, or length.
#[inline]
pub fn set_socket_broadcast(socket: RawFd, enabled: bool) -> Result<()> {
    let value = u32::from(enabled);
    // SAFETY: `value` is a live four-byte integer for the duration of the
    // direct syscall, and Linux validates the descriptor and option.
    decode(unsafe {
        syscall5(
            SYS_SETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_BROADCAST,
            (&value as *const u32) as usize,
            core::mem::size_of::<u32>(),
        )
    })
    .map(|_| ())
}

/// Gets Linux `SOL_SOCKET/SO_BROADCAST` without libc or TLS `errno`.
///
/// Linux returns this boolean socket option as a four-byte integer. A
/// nonzero value is `true`, matching Rustix and the Linux socket ABI.
#[inline]
pub fn socket_broadcast(socket: RawFd) -> Result<bool> {
    let mut value = MaybeUninit::<u32>::uninit();
    let mut length = core::mem::size_of::<u32>() as u32;
    // SAFETY: `value` and `length` are writable Linux socket-option output
    // storage for the duration of the direct syscall.
    decode(unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_BROADCAST,
            value.as_mut_ptr() as usize,
            (&mut length as *mut u32) as usize,
        )
    })?;
    if length as usize != core::mem::size_of::<u32>() {
        return Err(crate::Errno::INVAL);
    }
    // SAFETY: Linux initialized exactly the four bytes described by
    // `length` on successful `getsockopt`.
    Ok(unsafe { value.assume_init() } != 0)
}

/// Sets Linux `SOL_SOCKET/SO_OOBINLINE` without libc or TLS `errno`.
///
/// Linux represents this boolean socket option as a four-byte integer.
/// The value is kept entirely inside this typed seam; callers cannot
/// provide an arbitrary option level, name, pointer, or length.
#[inline]
pub fn set_socket_oobinline(socket: RawFd, enabled: bool) -> Result<()> {
    let value = u32::from(enabled);
    // SAFETY: `value` is a live four-byte integer for the duration of the
    // direct syscall, and Linux validates the descriptor and option.
    decode(unsafe {
        syscall5(
            SYS_SETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_OOBINLINE,
            (&value as *const u32) as usize,
            core::mem::size_of::<u32>(),
        )
    })
    .map(|_| ())
}

/// Gets Linux `SOL_SOCKET/SO_OOBINLINE` without libc or TLS `errno`.
///
/// Linux returns this boolean socket option as a four-byte integer. A
/// nonzero value is `true`, matching Rustix and the Linux socket ABI.
#[inline]
pub fn socket_oobinline(socket: RawFd) -> Result<bool> {
    let mut value = MaybeUninit::<u32>::uninit();
    let mut length = core::mem::size_of::<u32>() as u32;
    // SAFETY: `value` and `length` are writable Linux socket-option output
    // storage for the duration of the direct syscall.
    decode(unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_OOBINLINE,
            value.as_mut_ptr() as usize,
            (&mut length as *mut u32) as usize,
        )
    })?;
    if length as usize != core::mem::size_of::<u32>() {
        return Err(crate::Errno::INVAL);
    }
    // SAFETY: Linux initialized exactly the four bytes described by
    // `length` on successful `getsockopt`.
    Ok(unsafe { value.assume_init() } != 0)
}

/// Gets Linux `SOL_SOCKET/SO_TYPE` without libc or TLS `errno`.
///
/// Linux returns the socket type as a four-byte integer. The option level,
/// name, output storage, and length are fixed inside this typed seam.
#[inline]
pub fn socket_type(socket: RawFd) -> Result<u32> {
    let mut value = MaybeUninit::<u32>::uninit();
    let mut length = core::mem::size_of::<u32>() as u32;
    // SAFETY: `value` and `length` are writable Linux socket-option output
    // storage for the duration of the direct syscall.
    decode(unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_TYPE,
            value.as_mut_ptr() as usize,
            (&mut length as *mut u32) as usize,
        )
    })?;
    if length as usize != core::mem::size_of::<u32>() {
        return Err(crate::Errno::INVAL);
    }
    // SAFETY: Linux initialized exactly the four bytes described by
    // `length` on successful `getsockopt`.
    Ok(unsafe { value.assume_init() })
}

/// Gets Linux `SOL_SOCKET/SO_PROTOCOL` without libc or TLS `errno`.
///
/// Linux returns the protocol as a four-byte integer. The option level,
/// name, output storage, and length are fixed inside this typed seam.
#[inline]
pub fn socket_protocol(socket: RawFd) -> Result<u32> {
    let mut value = MaybeUninit::<u32>::uninit();
    let mut length = core::mem::size_of::<u32>() as u32;
    // SAFETY: `value` and `length` are writable Linux socket-option output
    // storage for the duration of the direct syscall.
    decode(unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_PROTOCOL,
            value.as_mut_ptr() as usize,
            (&mut length as *mut u32) as usize,
        )
    })?;
    if length as usize != core::mem::size_of::<u32>() {
        return Err(crate::Errno::INVAL);
    }
    // SAFETY: Linux initialized exactly the four bytes described by
    // `length` on successful `getsockopt`.
    Ok(unsafe { value.assume_init() })
}

/// Reads the pending Linux `SOL_SOCKET/SO_ERROR` value without libc or
/// TLS `errno`.
///
/// A successful `getsockopt` returns the pending socket error as a
/// non-negative integer.  The resolver transport uses this after a
/// nonblocking TCP connect becomes writable; keeping the query here makes
/// the pointer and four-byte output layout explicit at the shared kernel
/// boundary.
#[inline]
pub fn socket_error(socket: RawFd) -> Result<i32> {
    let mut value = MaybeUninit::<i32>::uninit();
    let mut length = core::mem::size_of::<i32>() as u32;
    // SAFETY: `value` and `length` are writable Linux socket-option output
    // storage for the duration of the direct syscall.
    decode(unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_ERROR,
            value.as_mut_ptr() as usize,
            (&mut length as *mut u32) as usize,
        )
    })?;
    if length as usize != core::mem::size_of::<i32>() {
        return Err(crate::Errno::INVAL);
    }
    // SAFETY: Linux initialized exactly the four bytes described by
    // `length` on successful `getsockopt`.
    Ok(unsafe { value.assume_init() })
}

/// Gets Linux `SOL_SOCKET/SO_COOKIE` without libc or TLS `errno`.
///
/// Linux returns the socket cookie as one private eight-byte integer. The
/// cookie's value is preserved exactly; only the option level, name,
/// output storage, and length are fixed inside this typed seam.
#[inline]
pub fn socket_cookie(socket: RawFd) -> Result<u64> {
    let mut value = MaybeUninit::<u64>::uninit();
    let mut length = core::mem::size_of::<u64>() as u32;
    // SAFETY: `value` and `length` are writable Linux socket-option output
    // storage for the duration of the direct syscall.
    decode(unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_COOKIE,
            value.as_mut_ptr() as usize,
            (&mut length as *mut u32) as usize,
        )
    })?;
    if length as usize != core::mem::size_of::<u64>() {
        return Err(crate::Errno::INVAL);
    }
    // SAFETY: Linux initialized exactly the eight bytes described by
    // `length` on successful `getsockopt`.
    Ok(unsafe { value.assume_init() })
}

/// Gets Linux `SOL_SOCKET/SO_DOMAIN` without libc or TLS `errno`.
///
/// Linux returns the address family as one private four-byte signed
/// integer. Conversion to the facade's narrower `AddressFamily` type is
/// intentionally performed above this direct wire seam.
#[inline]
pub fn socket_domain(socket: RawFd) -> Result<i32> {
    let mut value = MaybeUninit::<i32>::uninit();
    let mut length = core::mem::size_of::<i32>() as u32;
    // SAFETY: `value` and `length` are writable Linux socket-option output
    // storage for the duration of the direct syscall.
    decode(unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_DOMAIN,
            value.as_mut_ptr() as usize,
            (&mut length as *mut u32) as usize,
        )
    })?;
    if length as usize != core::mem::size_of::<i32>() {
        return Err(crate::Errno::INVAL);
    }
    // SAFETY: Linux initialized exactly the four bytes described by
    // `length` on successful `getsockopt`.
    Ok(unsafe { value.assume_init() })
}

/// Gets Linux `SOL_SOCKET/SO_ACCEPTCONN` without libc or TLS `errno`.
///
/// Linux returns the listening state as one private four-byte signed
/// integer. The safe facade intentionally applies Rustix's raw-nonzero
/// boolean conversion above this direct wire seam.
#[inline]
pub fn socket_acceptconn(socket: RawFd) -> Result<i32> {
    let mut value = MaybeUninit::<i32>::uninit();
    let mut length = core::mem::size_of::<i32>() as u32;
    // SAFETY: `value` and `length` are writable Linux socket-option output
    // storage for the duration of the direct syscall.
    decode(unsafe {
        syscall5(
            SYS_GETSOCKOPT,
            socket as usize,
            SOL_SOCKET,
            SO_ACCEPTCONN,
            value.as_mut_ptr() as usize,
            (&mut length as *mut u32) as usize,
        )
    })?;
    if length as usize != core::mem::size_of::<i32>() {
        return Err(crate::Errno::INVAL);
    }
    // SAFETY: Linux initialized exactly the four bytes described by
    // `length` on successful `getsockopt`.
    Ok(unsafe { value.assume_init() })
}

/// Enables listening for incoming connections without libc or TLS
/// `errno`.
#[inline]
pub fn listen(socket: RawFd, backlog: i32) -> Result<()> {
    // SAFETY: Linux validates the descriptor and signed backlog scalar;
    // this syscall has no pointer arguments.
    decode(unsafe { syscall2(SYS_LISTEN, socket as usize, backlog as usize) }).map(|_| ())
}

/// Accepts one pending connection with the Linux `accept` ABI.
///
/// # Safety
///
/// `address` and `address_length` must be null, or must satisfy the
/// Linux `accept` output-pointer contract: `address` points to writable
/// storage whose capacity is described by `*address_length`, and
/// `address_length` points to writable `socklen_t` storage. The caller is
/// responsible for validating any returned address bytes before decoding.
#[inline]
pub unsafe fn accept_raw(
    socket: RawFd,
    address: *mut u8,
    address_length: *mut u32,
) -> Result<RawFd> {
    // SAFETY: The caller owns the optional output-pointer contract; Linux
    // validates the descriptor and initializes the accepted descriptor.
    decode_i32(unsafe {
        syscall3(
            SYS_ACCEPT,
            socket as usize,
            address as usize,
            address_length as usize,
        )
    })
}

/// Accepts one pending connection with Linux `accept4` flags.
///
/// # Safety
///
/// `address` and `address_length` have the same nullable output-pointer
/// contract as [`accept_raw`]. `flags` must contain only Linux
/// `SOCK_CLOEXEC` and `SOCK_NONBLOCK` bits when called by a typed facade;
/// this raw seam forwards the word for the kernel to validate.
#[inline]
pub unsafe fn accept4_raw(
    socket: RawFd,
    address: *mut u8,
    address_length: *mut u32,
    flags: u32,
) -> Result<RawFd> {
    // SAFETY: The caller owns the optional output-pointer contract; Linux
    // validates the descriptor, flags, and initializes the accepted fd.
    decode_i32(unsafe {
        syscall4(
            SYS_ACCEPT4,
            socket as usize,
            address as usize,
            address_length as usize,
            flags as usize,
        )
    })
}

/// Shuts down one direction of a Linux socket without libc or TLS
/// `errno`.
#[inline]
pub fn shutdown(socket: RawFd, how: i32) -> Result<()> {
    // SAFETY: Linux validates the descriptor and shutdown mode; this
    // syscall has no pointer arguments.
    decode(unsafe { syscall2(SYS_SHUTDOWN, socket as usize, how as usize) }).map(|_| ())
}

/// Connects a socket to a caller-owned Linux socket address.
///
/// # Safety
///
/// `address` must point to a readable Linux socket address of
/// `address_length` bytes for the duration of the syscall.
#[inline]
pub unsafe fn connect_raw(
    socket: RawFd,
    address: *const u8,
    address_length: u32,
) -> Result<()> {
    // SAFETY: The caller owns the address pointer and length contract.
    decode(unsafe {
        syscall3(
            SYS_CONNECT,
            socket as usize,
            address as usize,
            address_length as usize,
        )
    })
    .map(|_| ())
}

/// Binds a socket to a caller-owned Linux socket address.
///
/// # Safety
///
/// `address` must point to a readable Linux socket address of
/// `address_length` bytes for the duration of the syscall.
#[inline]
pub unsafe fn bind_raw(socket: RawFd, address: *const u8, address_length: u32) -> Result<()> {
    // SAFETY: The caller owns the address pointer and length contract.
    decode(unsafe {
        syscall3(
            SYS_BIND,
            socket as usize,
            address as usize,
            address_length as usize,
        )
    })
    .map(|_| ())
}

/// Returns a socket's local address into caller-provided Linux storage.
///
/// # Safety
///
/// `address` must point to writable storage whose capacity is described by
/// `*address_length`, and `address_length` must point to writable Linux
/// `socklen_t` storage. On success Linux replaces the length with the
/// number of initialized address bytes; callers must validate that result
/// before interpreting the storage.
#[inline]
pub unsafe fn getsockname_raw(
    socket: RawFd,
    address: *mut u8,
    address_length: *mut u32,
) -> Result<()> {
    // SAFETY: The caller owns the output storage and socklen pointer
    // contracts; Linux validates the descriptor and reported capacity.
    decode(unsafe {
        syscall3(
            SYS_GETSOCKNAME,
            socket as usize,
            address as usize,
            address_length as usize,
        )
    })
    .map(|_| ())
}

/// Returns a socket's connected peer address into caller-provided Linux
/// storage.
///
/// # Safety
///
/// `address` must point to writable storage whose capacity is described by
/// `*address_length`, and `address_length` must point to writable Linux
/// `socklen_t` storage. On success Linux replaces the length with the
/// number of initialized address bytes; callers must validate that result
/// before interpreting the storage.
#[inline]
pub unsafe fn getpeername_raw(
    socket: RawFd,
    address: *mut u8,
    address_length: *mut u32,
) -> Result<()> {
    // SAFETY: The caller owns the output storage and socklen pointer
    // contracts; Linux validates the descriptor and reported capacity.
    decode(unsafe {
        syscall3(
            SYS_GETPEERNAME,
            socket as usize,
            address as usize,
            address_length as usize,
        )
    })
    .map(|_| ())
}

/// Creates a socket pair in caller-provided Linux `int[2]` storage.
///
/// # Safety
///
/// `sockets` must point to writable storage for two Linux `int` values or
/// be a pointer deliberately forwarded to preserve C ABI `EFAULT`
/// behavior.
#[inline]
pub unsafe fn socketpair_raw(
    domain: i32,
    type_and_flags: u32,
    protocol: i32,
    sockets: *mut RawFd,
) -> Result<()> {
    // SAFETY: The caller owns the output-pointer contract. Linux validates
    // the domain, type/flags, and protocol.
    decode(unsafe {
        syscall4(
            SYS_SOCKETPAIR,
            domain as usize,
            type_and_flags as usize,
            protocol as usize,
            sockets as usize,
        )
    })
    .map(|_| ())
}

/// Creates a socket pair without using libc or TLS `errno`.
#[inline]
pub fn socketpair(domain: i32, type_and_flags: u32, protocol: i32) -> Result<(RawFd, RawFd)> {
    let mut sockets = MaybeUninit::<[RawFd; 2]>::uninit();
    // SAFETY: `sockets` supplies output storage for exactly two Linux
    // descriptors and a successful syscall initializes both values.
    unsafe {
        socketpair_raw(
            domain,
            type_and_flags,
            protocol,
            sockets.as_mut_ptr().cast(),
        )?
    };
    // SAFETY: The successful syscall above initialized both descriptors.
    let [first, second] = unsafe { sockets.assume_init() };
    Ok((first, second))
}

/// Sends bytes with the Linux `sendto` ABI.
///
/// # Safety
///
/// `buffer` must be readable for `length` bytes. When non-null, `address`
/// must point to a readable Linux `sockaddr` of `address_length` bytes.
#[inline]
pub unsafe fn sendto_raw(
    socket: RawFd,
    buffer: *const u8,
    length: usize,
    flags: u32,
    address: *const u8,
    address_length: u32,
) -> Result<usize> {
    // SAFETY: The caller owns the buffer and optional address contracts.
    decode(unsafe {
        syscall6(
            SYS_SENDTO,
            socket as usize,
            buffer as usize,
            length,
            flags as usize,
            address as usize,
            address_length as usize,
        )
    })
}

/// Receives bytes with the Linux `recvfrom` ABI.
///
/// # Safety
///
/// `buffer` must be writable for `length` bytes. The optional address and
/// address-length pointers must satisfy the Linux `recvfrom` ABI.
#[inline]
pub unsafe fn recvfrom_raw(
    socket: RawFd,
    buffer: *mut u8,
    length: usize,
    flags: u32,
    address: *mut u8,
    address_length: *mut u32,
) -> Result<usize> {
    // SAFETY: The caller owns every output-pointer contract.
    decode(unsafe {
        syscall6(
            SYS_RECVFROM,
            socket as usize,
            buffer as usize,
            length,
            flags as usize,
            address as usize,
            address_length as usize,
        )
    })
}

/// One Linux LP64 message header assembled privately for `sendmsg` and
/// `recvmsg`. The public native facade supplies only typed borrowed iovecs;
/// callers cannot provide a raw `msghdr`, ancillary pointer, or address
/// pointer through this seam.
#[repr(C)]
struct MessageHeader {
    name: *mut u8,
    name_length: u32,
    iovecs: *mut Iovec,
    iovec_count: usize,
    control: *mut u8,
    control_length: usize,
    flags: u32,
}

const _: () = assert!(core::mem::size_of::<MessageHeader>() == 56);
const _: () = assert!(core::mem::align_of::<MessageHeader>() == 8);
const _: () = assert!(core::mem::offset_of!(MessageHeader, name) == 0);
const _: () = assert!(core::mem::offset_of!(MessageHeader, name_length) == 8);
const _: () = assert!(core::mem::offset_of!(MessageHeader, iovecs) == 16);
const _: () = assert!(core::mem::offset_of!(MessageHeader, iovec_count) == 24);
const _: () = assert!(core::mem::offset_of!(MessageHeader, control) == 32);
const _: () = assert!(core::mem::offset_of!(MessageHeader, control_length) == 40);
const _: () = assert!(core::mem::offset_of!(MessageHeader, flags) == 48);

/// Sends one ordinary vectored message on a connected socket through the
/// Linux `sendmsg` ABI.
///
/// # Safety
///
/// `iovecs` must be null or point to `count` initialized [`Iovec`] records
/// readable for the duration of the call. Every non-empty iovec range
/// must be valid for immutable access for its `iov_len` bytes. A null
/// iovec pointer is permitted only when `count` is zero. The descriptor's
/// socket validity is the caller's responsibility.
#[inline]
pub unsafe fn sendmsg_raw(
    socket: RawFd,
    iovecs: *const Iovec,
    count: usize,
    flags: u32,
) -> Result<usize> {
    let header = MessageHeader {
        name: core::ptr::null_mut(),
        name_length: 0,
        iovecs: iovecs.cast_mut(),
        iovec_count: count,
        control: core::ptr::null_mut(),
        control_length: 0,
        flags: 0,
    };
    // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
    // validity contracts; the private header has no name or control data.
    decode(unsafe {
        syscall3(
            SYS_SENDMSG,
            socket as usize,
            (&header as *const MessageHeader) as usize,
            flags as usize,
        )
    })
}

/// Receives one ordinary vectored message from a socket through the Linux
/// `recvmsg` ABI and returns the kernel byte count plus returned message
/// flags.
///
/// # Safety
///
/// `iovecs` must be null or point to `count` initialized [`Iovec`] records
/// readable for the duration of the call. Every non-empty iovec range
/// must be valid for mutable access for its `iov_len` bytes, and those
/// ranges must be pairwise disjoint. A null iovec pointer is permitted
/// only when `count` is zero. The descriptor's socket validity is the
/// caller's responsibility.
#[inline]
pub unsafe fn recvmsg_raw(
    socket: RawFd,
    iovecs: *const Iovec,
    count: usize,
    flags: u32,
) -> Result<(usize, u32)> {
    let mut header = MessageHeader {
        name: core::ptr::null_mut(),
        name_length: 0,
        iovecs: iovecs.cast_mut(),
        iovec_count: count,
        control: core::ptr::null_mut(),
        control_length: 0,
        flags: 0,
    };
    // SAFETY: The caller supplies the iovec-array and pointed-to-buffer
    // validity contracts; the private header has no name or control data.
    let bytes = decode(unsafe {
        syscall3(
            SYS_RECVMSG,
            socket as usize,
            (&mut header as *mut MessageHeader) as usize,
            flags as usize,
        )
    })?;
    Ok((bytes, header.flags))
}

/// Sends an array of private Linux LP64 `mmsghdr` records.
///
/// The records are assembled by the native facade. This raw seam keeps
/// the Linux `mmsghdr` layout out of the public Rust API while preserving
/// the kernel's count-returning partial-success contract.
///
/// # Safety
///
/// `messages` must be null when `count` is zero, or point to `count`
/// initialized, contiguous Linux LP64 `mmsghdr` records. Every nested
/// header and iovec must satisfy Linux's read-only send contract, and the
/// records remain valid for the syscall duration.
#[inline]
pub unsafe fn sendmmsg_raw(
    socket: RawFd,
    messages: *mut u8,
    count: u32,
    flags: u32,
) -> Result<usize> {
    // SAFETY: The caller owns the private mmsghdr array and its nested
    // iovec/source-buffer contracts.
    decode(unsafe {
        syscall4(
            SYS_SENDMMSG,
            socket as usize,
            messages as usize,
            count as usize,
            flags as usize,
        )
    })
}

/// Receives an array of private Linux LP64 `mmsghdr` records.
///
/// `timeout` is the optional mutable Linux `timespec` consumed and
/// updated by `recvmmsg`; callers must observe the value after the call.
/// A positive return is the number of messages initialized, even if a
/// later message would have blocked or failed.
///
/// # Safety
///
/// `messages` must be null when `count` is zero, or point to `count`
/// initialized, contiguous Linux LP64 `mmsghdr` records. Every nested
/// header and iovec must satisfy Linux's writable receive contract, and
/// `timeout` must be null or point to writable `timespec` storage. All
/// pointed-to records and buffers remain valid for the syscall duration.
#[inline]
pub unsafe fn recvmmsg_raw(
    socket: RawFd,
    messages: *mut u8,
    count: u32,
    flags: u32,
    timeout: *mut u8,
) -> Result<usize> {
    // SAFETY: The caller owns the private mmsghdr array, timeout, and all
    // nested destination-buffer contracts.
    decode(unsafe {
        syscall5(
            SYS_RECVMMSG,
            socket as usize,
            messages as usize,
            count as usize,
            flags as usize,
            timeout as usize,
        )
    })
}
