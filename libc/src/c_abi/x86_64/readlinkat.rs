//! Selected static Linux/x86-64 `readlinkat` C ABI leaf.
//!
//! This leaf owns exactly `readlinkat(int, const char *, char *, size_t)`. It
//! preserves musl 1.2.6's direct `SYS_readlinkat` body from
//! `src/unistd/readlinkat.c`: the caller's directory descriptor, pathname,
//! caller-owned output pointer, and capacity reach Linux 5.10 unchanged when
//! capacity is nonzero. For a zero capacity, musl supplies one stack dummy
//! byte to Linux and converts a positive byte count back to zero; the caller's
//! buffer remains untouched. It shares only the raw Linux/x86-64 syscall
//! boundary and selected initial-TLS `errno` translator. It is not ordinary
//! `readlink`, `linkat`/`symlinkat`/`unlinkat`, pathname parsing or
//! canonicalization, CWD state, directory streams, allocation, cancellation,
//! a Rust facade, libc.so, CRT, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/unistd/readlinkat.c` replaces a zero-size caller output with local
//! `char dummy[1]`, issues `__syscall(SYS_readlinkat, fd, path, buf, bufsize)`,
//! and returns zero when that dummy receives a positive result. Linux 5.10
//! has the direct x86-64 request, so this private static leaf adds no fallback,
//! retry, path copy, allocation, or policy layer.

use core::ffi::{c_char, c_int};

use super::{c_ssize_status, raw_syscall};

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
    assert!(core::mem::size_of::<isize>() == 8);
};

/// Read one symbolic-link target into caller-owned non-NUL-terminated bytes.
///
/// # Safety
///
/// `path` must remain a readable NUL-terminated pathname for the call, unless
/// the caller deliberately requests Linux's `EFAULT` result. When `capacity`
/// is nonzero, `buffer` must designate writable storage for exactly that many
/// bytes, unless the caller deliberately requests a raw pointer error. A zero
/// capacity accepts any `buffer` value: this leaf uses only its own one-byte
/// stack dummy. The caller owns directory-descriptor lifetime, pathname
/// resolution races, output lifetime, and every interpretation of the raw
/// non-NUL-terminated result.
#[no_mangle]
pub unsafe extern "C" fn readlinkat(
    directory_descriptor: c_int,
    path: *const c_char,
    buffer: *mut c_char,
    capacity: usize,
) -> isize {
    let mut dummy = 0u8;
    let (kernel_buffer, kernel_capacity) = if capacity == 0 {
        (&mut dummy as *mut u8 as *mut c_char, 1usize)
    } else {
        (buffer, capacity)
    };
    // SAFETY: Linux/x86-64 readlinkat=267 receives dirfd/path/output/capacity
    // in rdi/rsi/rdx/r10 and validates the caller-owned descriptor, pathname,
    // and nonzero output pointer itself. The zero-capacity dummy is writable
    // local storage matching musl's bounded compatibility spelling.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_READLINKAT,
            i64::from(directory_descriptor),
            path as usize as i64,
            kernel_buffer as usize as i64,
            kernel_capacity as i64,
        )
    };
    if capacity == 0 && result > 0 {
        0
    } else {
        c_ssize_status(result)
    }
}
