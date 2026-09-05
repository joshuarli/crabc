//! Selected static Linux/x86-64 C socket-transport boundary.
//!
//! This leaf owns one closed, basic C socket lifecycle and byte-transport
//! block: `socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`,
//! `connect`, `send`, `recv`, `sendto`, `recvfrom`, `shutdown`,
//! `getsockname`, and `getpeername`. It composes the Linux syscall register
//! boundary, C `errno`, and the owned runtime's cancellation window. It is not
//! socket-option or interface-ioctl support; vector, batched, or ancillary
//! message I/O; resolver or netdb state; C path/open/fcntl APIs; a pthread
//! lifecycle owner; a general C/POSIX runtime; libc.so; CRT; dynamic
//! TLS; loader; sysroot; allocator; or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/network/socket.c`, `src/network/socketpair.c`,
//!   `src/network/bind.c`, `src/network/listen.c`,
//!   `src/network/accept.c`, `src/network/accept4.c`, and
//!   `src/network/connect.c` map to the correspondingly named wrappers.
//! - `src/network/send.c` and `src/network/recv.c` map to [`send`] and
//!   [`recv`], whose source routes through `sendto` and `recvfrom` with null
//!   peer-address arguments.
//! - `src/network/sendto.c`, `src/network/recvfrom.c`,
//!   `src/network/shutdown.c`, `src/network/getsockname.c`, and
//!   `src/network/getpeername.c` map to the correspondingly named wrappers.
//!
//! Musl's socket, socketpair, and accept4 sources retain fallback algorithms
//! for kernels that lack atomic descriptor flags. Linux 5.10 supplies
//! `SOCK_CLOEXEC`, `SOCK_NONBLOCK`, and `accept4`, so this target-specific
//! leaf calls their direct syscalls and deliberately carries no pre-baseline
//! fcntl fallback. Musl also routes accept, connect, sendto, and recvfrom
//! through pthread cancellation-point machinery. The owned runtime preserves
//! those cancellation points; standalone archive selections retain direct
//! syscalls. Linux 5.10 makes the source's older-kernel fallbacks unnecessary.

use core::ffi::{c_int, c_uint, c_void};

use super::{c_ssize_status, c_status, raw_syscall};

/// Create one socket through Linux `socket(2)`.
///
/// The domain, type, protocol, and any atomic descriptor flags are passed
/// unchanged to Linux 5.10. This target does not emulate older-kernel flag
/// handling.
#[no_mangle]
pub extern "C" fn socket(domain: c_int, type_: c_int, protocol: c_int) -> c_int {
    // SAFETY: every argument is a scalar Linux socket word; the kernel owns
    // validation and descriptor allocation.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SOCKET,
            i64::from(domain),
            i64::from(type_),
            i64::from(protocol),
        )
    };
    c_status(result)
}

/// Create a connected local socket pair through Linux `socketpair(2)`.
///
/// # Safety
///
/// On success, `descriptors` must designate two writable x86 `int` words for
/// the kernel's duration. The caller owns the returned descriptor lifetimes
/// and any concurrent endpoint policy. This leaf does not provide socket or
/// pthread ownership management.
#[no_mangle]
pub unsafe extern "C" fn socketpair(
    domain: c_int,
    type_: c_int,
    protocol: c_int,
    descriptors: *mut c_int,
) -> c_int {
    // SAFETY: the caller owns the two-word output storage; scalar socket
    // arguments pass unchanged in Linux x86 rdi/rsi/rdx/r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_SOCKETPAIR,
            i64::from(domain),
            i64::from(type_),
            i64::from(protocol),
            descriptors as usize as i64,
        )
    };
    c_status(result)
}

/// Bind one socket to a caller-described address through Linux `bind(2)`.
///
/// # Safety
///
/// `address` must designate at least `address_length` readable bytes in one
/// kernel-recognized sockaddr form for the syscall's duration. The caller
/// owns address-family, namespace, and descriptor-lifetime policy.
#[no_mangle]
pub unsafe extern "C" fn bind(
    file_descriptor: c_int,
    address: *const c_void,
    address_length: c_uint,
) -> c_int {
    // SAFETY: the caller supplies the complete raw sockaddr input contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_BIND,
            i64::from(file_descriptor),
            address as usize as i64,
            i64::from(address_length),
        )
    };
    c_status(result)
}

/// Mark one stream socket as a listener through Linux `listen(2)`.
#[no_mangle]
pub extern "C" fn listen(file_descriptor: c_int, backlog: c_int) -> c_int {
    // SAFETY: both inputs are scalar Linux socket words.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_LISTEN,
            i64::from(file_descriptor),
            i64::from(backlog),
        )
    };
    c_status(result)
}

/// Accept one pending connection through Linux `accept(2)`.
///
/// # Safety
///
/// When `address` and `address_length` are non-null, they must designate a
/// writable sockaddr output region and writable x86 `socklen_t` word whose
/// capacity is described by that word. Passing both null follows Linux's
/// address-omission form. The caller owns descriptor lifetime and blocking
/// policy. The owned runtime supplies musl's pthread cancellation point.
#[no_mangle]
pub unsafe extern "C" fn accept(
    file_descriptor: c_int,
    address: *mut c_void,
    address_length: *mut c_uint,
) -> c_int {
    // SAFETY: the caller supplies Linux's optional paired sockaddr output
    // contract. The kernel validates the descriptor and copies output.
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_ACCEPT,
                i64::from(file_descriptor),
                address as usize as i64,
                address_length as usize as i64,
                0,
                0,
                0,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall3(
                raw_syscall::SYS_ACCEPT,
                i64::from(file_descriptor),
                address as usize as i64,
                address_length as usize as i64,
            )
        }
    };
    c_status(result)
}

/// Accept one pending connection with Linux 5.10 atomic descriptor flags.
///
/// # Safety
///
/// The optional address output has the same obligations as [`accept`].
/// `flags` passes directly to Linux; this leaf deliberately has no legacy
/// `accept` plus fcntl fallback. The caller owns descriptor lifetime and any
/// blocking/cancellation policy.
#[no_mangle]
pub unsafe extern "C" fn accept4(
    file_descriptor: c_int,
    address: *mut c_void,
    address_length: *mut c_uint,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller supplies Linux's optional paired sockaddr output
    // contract; x86's fourth syscall argument is r10.
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_ACCEPT4,
                i64::from(file_descriptor),
                address as usize as i64,
                address_length as usize as i64,
                i64::from(flags),
                0,
                0,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall4(
                raw_syscall::SYS_ACCEPT4,
                i64::from(file_descriptor),
                address as usize as i64,
                address_length as usize as i64,
                i64::from(flags),
            )
        }
    };
    c_status(result)
}

/// Connect one socket to a caller-described peer through Linux `connect(2)`.
///
/// # Safety
///
/// `address` must designate at least `address_length` readable bytes in one
/// kernel-recognized sockaddr form for the syscall's duration. The caller
/// owns descriptor lifetime, nonblocking state, and signal/cancellation
/// policy. This is a cancellation point in the owned runtime.
#[no_mangle]
pub unsafe extern "C" fn connect(
    file_descriptor: c_int,
    address: *const c_void,
    address_length: c_uint,
) -> c_int {
    // SAFETY: the caller supplies the complete raw sockaddr input contract.
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_CONNECT,
                i64::from(file_descriptor),
                address as usize as i64,
                i64::from(address_length),
                0,
                0,
                0,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall3(
                raw_syscall::SYS_CONNECT,
                i64::from(file_descriptor),
                address as usize as i64,
                i64::from(address_length),
            )
        }
    };
    c_status(result)
}

/// Send bytes on one connected socket through Linux `sendto(2)`.
///
/// This preserves musl's `send` shape by supplying null peer-address words.
///
/// # Safety
///
/// `buffer` must designate `count` readable bytes when Linux examines it.
/// The caller owns descriptor lifetime, blocking state, and SIGPIPE policy.
/// This is a cancellation point in the owned runtime.
#[no_mangle]
pub unsafe extern "C" fn send(
    file_descriptor: c_int,
    buffer: *const c_void,
    count: usize,
    flags: c_int,
) -> isize {
    // SAFETY: the caller supplies the complete raw send buffer contract;
    // Linux x86 receives its final peer-address words in r8/r9.
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_SENDTO,
                i64::from(file_descriptor),
                buffer as usize as i64,
                count as i64,
                i64::from(flags),
                0,
                0,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall6(
                raw_syscall::SYS_SENDTO,
                i64::from(file_descriptor),
                buffer as usize as i64,
                count as i64,
                i64::from(flags),
                0,
                0,
            )
        }
    };
    c_ssize_status(result)
}

/// Receive bytes from one connected socket through Linux `recvfrom(2)`.
///
/// This preserves musl's `recv` shape by supplying null source-address words.
///
/// # Safety
///
/// `buffer` must designate `count` writable bytes when Linux examines it.
/// The caller owns descriptor lifetime, blocking state, and signal/cancellation
/// policy. This is a cancellation point in the owned runtime.
#[no_mangle]
pub unsafe extern "C" fn recv(
    file_descriptor: c_int,
    buffer: *mut c_void,
    count: usize,
    flags: c_int,
) -> isize {
    // SAFETY: the caller supplies the complete raw receive buffer contract;
    // Linux x86 receives its final source-address words in r8/r9.
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_RECVFROM,
                i64::from(file_descriptor),
                buffer as usize as i64,
                count as i64,
                i64::from(flags),
                0,
                0,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall6(
                raw_syscall::SYS_RECVFROM,
                i64::from(file_descriptor),
                buffer as usize as i64,
                count as i64,
                i64::from(flags),
                0,
                0,
            )
        }
    };
    c_ssize_status(result)
}

/// Send bytes to one caller-described peer through Linux `sendto(2)`.
///
/// # Safety
///
/// `buffer` must designate `count` readable bytes and `address` must
/// designate `address_length` readable sockaddr bytes when Linux examines
/// them. The caller owns descriptor lifetime, blocking state, and SIGPIPE or
/// cancellation policy. The owned runtime supplies the cancellation point.
#[no_mangle]
pub unsafe extern "C" fn sendto(
    file_descriptor: c_int,
    buffer: *const c_void,
    count: usize,
    flags: c_int,
    address: *const c_void,
    address_length: c_uint,
) -> isize {
    // SAFETY: the caller supplies both raw buffer and sockaddr input
    // contracts; Linux x86 passes arguments four through six in r10/r8/r9.
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_SENDTO,
                i64::from(file_descriptor),
                buffer as usize as i64,
                count as i64,
                i64::from(flags),
                address as usize as i64,
                i64::from(address_length),
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall6(
                raw_syscall::SYS_SENDTO,
                i64::from(file_descriptor),
                buffer as usize as i64,
                count as i64,
                i64::from(flags),
                address as usize as i64,
                i64::from(address_length),
            )
        }
    };
    c_ssize_status(result)
}

/// Receive bytes and an optional source address through Linux `recvfrom(2)`.
///
/// # Safety
///
/// `buffer` must designate `count` writable bytes when Linux examines it.
/// When `address` and `address_length` are non-null, they must designate a
/// writable sockaddr output region and writable x86 `socklen_t` word whose
/// capacity is described by that word. Passing both null follows Linux's
/// source-address omission form. The caller owns descriptor lifetime and
/// blocking/cancellation policy.
#[no_mangle]
pub unsafe extern "C" fn recvfrom(
    file_descriptor: c_int,
    buffer: *mut c_void,
    count: usize,
    flags: c_int,
    address: *mut c_void,
    address_length: *mut c_uint,
) -> isize {
    // SAFETY: the caller supplies raw receive buffer and optional paired
    // sockaddr output contracts; Linux x86 uses r10/r8/r9 for their tail.
    let result = unsafe {
        #[cfg(feature = "x86-owned-static-runtime")]
        {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_RECVFROM,
                i64::from(file_descriptor),
                buffer as usize as i64,
                count as i64,
                i64::from(flags),
                address as usize as i64,
                address_length as usize as i64,
            )
        }
        #[cfg(not(feature = "x86-owned-static-runtime"))]
        {
            raw_syscall::syscall6(
                raw_syscall::SYS_RECVFROM,
                i64::from(file_descriptor),
                buffer as usize as i64,
                count as i64,
                i64::from(flags),
                address as usize as i64,
                address_length as usize as i64,
            )
        }
    };
    c_ssize_status(result)
}

/// Shut down one socket direction through Linux `shutdown(2)`.
#[no_mangle]
pub extern "C" fn shutdown(file_descriptor: c_int, how: c_int) -> c_int {
    // SAFETY: both inputs are scalar Linux socket words.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_SHUTDOWN,
            i64::from(file_descriptor),
            i64::from(how),
        )
    };
    c_status(result)
}

/// Report one socket's local address through Linux `getsockname(2)`.
///
/// # Safety
///
/// `address` and `address_length` must designate a writable sockaddr output
/// region and writable x86 `socklen_t` word whose capacity is described by
/// that word. The caller owns descriptor lifetime and address-family policy.
#[no_mangle]
pub unsafe extern "C" fn getsockname(
    file_descriptor: c_int,
    address: *mut c_void,
    address_length: *mut c_uint,
) -> c_int {
    // SAFETY: the caller supplies Linux's sockaddr output contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_GETSOCKNAME,
            i64::from(file_descriptor),
            address as usize as i64,
            address_length as usize as i64,
        )
    };
    c_status(result)
}

/// Report one socket's peer address through Linux `getpeername(2)`.
///
/// # Safety
///
/// `address` and `address_length` must designate a writable sockaddr output
/// region and writable x86 `socklen_t` word whose capacity is described by
/// that word. The caller owns descriptor lifetime and address-family policy.
#[no_mangle]
pub unsafe extern "C" fn getpeername(
    file_descriptor: c_int,
    address: *mut c_void,
    address_length: *mut c_uint,
) -> c_int {
    // SAFETY: the caller supplies Linux's sockaddr output contract.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_GETPEERNAME,
            i64::from(file_descriptor),
            address as usize as i64,
            address_length as usize as i64,
        )
    };
    c_status(result)
}
