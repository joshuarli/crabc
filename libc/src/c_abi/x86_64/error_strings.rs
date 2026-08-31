//! Selected static Linux/x86-64 C error-string boundary.
//!
//! This leaf owns exactly `strerror`, `strerror_r`, and musl's weak
//! same-address `__xpg_strerror_r` alias. It is immutable, allocation-free,
//! and fixed to the project's admitted C/POSIX/C.UTF-8 message set. It does
//! not read or write `errno`, TLS, locale objects, message catalogs, locks, or
//! process state. The adjacent `locale_error_strings` leaf owns only the
//! fixed-profile `__strerror_l`/`strerror_l` spelling over this same immutable
//! lookup. This leaf itself is not `strsignal`, `perror`, the err/warn family,
//! `abort`, libc.so, a CRT, a loader, a sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/errno/__strerror.h` maps each x86 Linux errno value to the exact
//!   immutable English message below and uses `"No error information"` for
//!   zero, table holes, and nonnegative values past the table.
//! - `src/errno/strerror.c` maps the selected C-locale lookup to `strerror`.
//!   Its locale-argument spelling maps in the adjacent narrow ABI leaf because
//!   all admitted project locales share these messages.
//! - `src/string/strerror_r.c` maps to the caller-buffer copy/truncation path
//!   and its weak `__xpg_strerror_r` alias.
//!
//! Musl's source does not guard negative indices before indexing its lookup
//! table. Negative values are outside the native differential's defined errno
//! domain; this leaf maps them to the immutable catch-all rather than perform
//! an out-of-bounds read. No valid Linux x86 errno result is changed.

use core::ffi::{c_char, c_int};

const ERANGE: c_int = 34;
const NO_ERROR_INFORMATION: &[u8] = b"No error information\0";

/// Return the fixed musl C-locale message for one Linux/x86 errno value.
///
/// This parent-local helper is shared by the selected bare `printf` `%m`
/// adapter. Keeping that adapter on the immutable table avoids turning one
/// formatter conversion into an interposable C `strerror` call or a broader
/// error-reporting boundary.
#[inline]
pub(super) fn error_message(error: c_int) -> &'static [u8] {
    match error {
        1 => b"Operation not permitted\0",
        2 => b"No such file or directory\0",
        3 => b"No such process\0",
        4 => b"Interrupted system call\0",
        5 => b"I/O error\0",
        6 => b"No such device or address\0",
        7 => b"Argument list too long\0",
        8 => b"Exec format error\0",
        9 => b"Bad file descriptor\0",
        10 => b"No child process\0",
        11 => b"Resource temporarily unavailable\0",
        12 => b"Out of memory\0",
        13 => b"Permission denied\0",
        14 => b"Bad address\0",
        15 => b"Block device required\0",
        16 => b"Resource busy\0",
        17 => b"File exists\0",
        18 => b"Cross-device link\0",
        19 => b"No such device\0",
        20 => b"Not a directory\0",
        21 => b"Is a directory\0",
        22 => b"Invalid argument\0",
        23 => b"Too many open files in system\0",
        24 => b"No file descriptors available\0",
        25 => b"Not a tty\0",
        26 => b"Text file busy\0",
        27 => b"File too large\0",
        28 => b"No space left on device\0",
        29 => b"Invalid seek\0",
        30 => b"Read-only file system\0",
        31 => b"Too many links\0",
        32 => b"Broken pipe\0",
        33 => b"Domain error\0",
        34 => b"Result not representable\0",
        35 => b"Resource deadlock would occur\0",
        36 => b"Filename too long\0",
        37 => b"No locks available\0",
        38 => b"Function not implemented\0",
        39 => b"Directory not empty\0",
        40 => b"Symbolic link loop\0",
        42 => b"No message of desired type\0",
        43 => b"Identifier removed\0",
        60 => b"Device not a stream\0",
        61 => b"No data available\0",
        62 => b"Device timeout\0",
        63 => b"Out of streams resources\0",
        67 => b"Link has been severed\0",
        71 => b"Protocol error\0",
        72 => b"Multihop attempted\0",
        74 => b"Bad message\0",
        75 => b"Value too large for data type\0",
        77 => b"File descriptor in bad state\0",
        84 => b"Illegal byte sequence\0",
        88 => b"Not a socket\0",
        89 => b"Destination address required\0",
        90 => b"Message too large\0",
        91 => b"Protocol wrong type for socket\0",
        92 => b"Protocol not available\0",
        93 => b"Protocol not supported\0",
        94 => b"Socket type not supported\0",
        95 => b"Not supported\0",
        96 => b"Protocol family not supported\0",
        97 => b"Address family not supported by protocol\0",
        98 => b"Address in use\0",
        99 => b"Address not available\0",
        100 => b"Network is down\0",
        101 => b"Network unreachable\0",
        102 => b"Connection reset by network\0",
        103 => b"Connection aborted\0",
        104 => b"Connection reset by peer\0",
        105 => b"No buffer space available\0",
        106 => b"Socket is connected\0",
        107 => b"Socket not connected\0",
        108 => b"Cannot send after socket shutdown\0",
        110 => b"Operation timed out\0",
        111 => b"Connection refused\0",
        112 => b"Host is down\0",
        113 => b"Host is unreachable\0",
        114 => b"Operation already in progress\0",
        115 => b"Operation in progress\0",
        116 => b"Stale file handle\0",
        117 => b"Data consistency error\0",
        119 => b"Resource not available\0",
        121 => b"Remote I/O error\0",
        122 => b"Quota exceeded\0",
        123 => b"No medium found\0",
        124 => b"Wrong medium type\0",
        125 => b"Operation canceled\0",
        126 => b"Required key not available\0",
        127 => b"Key has expired\0",
        128 => b"Key has been revoked\0",
        129 => b"Key was rejected by service\0",
        130 => b"Previous owner died\0",
        131 => b"State not recoverable\0",
        _ => NO_ERROR_INFORMATION,
    }
}

// Musl's weak_alias(strerror_r, __xpg_strerror_r) requires equal ELF symbol
// values. A Rust wrapper would have a different address and would silently
// weaken the pinned static-ABI contract.
core::arch::global_asm!(
    ".weak __xpg_strerror_r",
    ".set __xpg_strerror_r, strerror_r",
);

/// Return one immutable C-locale message for `error`.
///
/// The returned storage is process-static and must not be modified or freed.
#[no_mangle]
pub extern "C" fn strerror(error: c_int) -> *mut c_char {
    error_message(error).as_ptr().cast_mut().cast::<c_char>()
}

/// Copy one immutable C-locale error message into caller-owned storage.
///
/// # Safety
///
/// When `capacity` is nonzero, `buffer` must designate exactly `capacity`
/// writable bytes. The destination must not overlap the process-static source
/// message. A null buffer is permitted only when capacity is zero.
#[no_mangle]
pub unsafe extern "C" fn strerror_r(
    error: c_int,
    buffer: *mut c_char,
    capacity: usize,
) -> c_int {
    let message = error_message(error);
    let message_length = message.len().wrapping_sub(1);
    if message_length >= capacity {
        if capacity != 0 {
            let copy_length = capacity.wrapping_sub(1);
            let mut index = 0usize;
            while index < copy_length {
                // SAFETY: the message length is at least capacity, and the
                // caller supplies the exact writable destination range.
                unsafe {
                    buffer
                        .add(index)
                        .write(message.as_ptr().add(index).read() as c_char);
                }
                index = index.wrapping_add(1);
            }
            // SAFETY: nonzero capacity makes its final byte writable.
            unsafe { buffer.add(copy_length).write(0) };
        }
        return ERANGE;
    }

    let copy_length = message_length.wrapping_add(1);
    let mut index = 0usize;
    while index < copy_length {
        // SAFETY: copy_length includes exactly the source NUL, and the caller
        // supplies at least that many writable bytes on this success path.
        unsafe {
            buffer
                .add(index)
                .write(message.as_ptr().add(index).read() as c_char);
        }
        index = index.wrapping_add(1);
    }
    0
}
