//! Selected Linux/x86-64 C string-duplication allocation client.
//!
//! This opt-in leaf owns exactly POSIX `strdup` and `strndup`. It reaches the
//! separately audited weak `malloc` C ABI entry through an external symbol,
//! so its returned storage is released by the same selected `free` boundary.
//! It is not an allocator implementation, allocation-family completion,
//! allocator lifecycle, string/token/locale subsystem, dynamic runtime, CRT,
//! loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/string/strdup.c` maps to [`strdup`]: measure the complete C string,
//!   allocate its terminator-inclusive byte count, then copy that exact range.
//! - `src/string/strndup.c` maps to [`strndup`]: measure at most the supplied
//!   readable range, allocate its terminator-inclusive length, copy only that
//!   prefix, and append a terminator.
//!
//! Musl reaches the same `malloc` ABI after its `strlen`/`strnlen` helpers.
//! This scalar Rust translation keeps every source read inside the caller's
//! C-string or explicit `strndup` bound. The otherwise-unrepresentable
//! terminator-inclusive `usize` overflow publishes `ENOMEM` before allocation;
//! ordinary allocation failure is owned by the selected allocator wrapper.

use core::ffi::{c_char, c_int, c_void};

use super::errno;

const ENOMEM: c_int = 12;

// Do not name a Rust-level dependency on the private allocator module. The
// static archive records this as the public `malloc` symbol dependency, so the
// dedicated gate can prove that the existing weak wrapper, rather than musl,
// supplies it to this client object.
unsafe extern "C" {
    #[link_name = "malloc"]
    fn cabi_allocator_malloc(size: usize) -> *mut c_void;
}

/// Allocate and copy exactly `length` readable source bytes plus one NUL.
///
/// # Safety
///
/// `source` must designate at least `length` readable bytes. It need not be
/// NUL-terminated within that range because the caller owns the output
/// terminator. The selected external `malloc` entry must retain its C ABI.
#[inline]
unsafe fn duplicate_prefix(source: *const u8, length: usize) -> *mut c_char {
    let Some(allocation_size) = length.checked_add(1) else {
        // SAFETY: this is the selected C ABI's one calling-thread errno slot.
        unsafe { errno::set_errno(ENOMEM) };
        return core::ptr::null_mut();
    };
    // SAFETY: the public C ABI call has exactly one LP64 `size_t` argument.
    let destination = unsafe { cabi_allocator_malloc(allocation_size) }.cast::<u8>();
    if destination.is_null() {
        // The selected allocator wrapper owns regular allocation-failure errno.
        return core::ptr::null_mut();
    }

    let mut input = source;
    let mut output = destination;
    let mut remaining = length;
    while remaining != 0 {
        // SAFETY: the helper contract reserves this source byte and output
        // allocation byte on every retained iteration.
        unsafe { output.write(input.read()) };
        // SAFETY: consuming one proven source/output byte leaves the following
        // byte valid until the exact bounded loop finishes.
        input = unsafe { input.add(1) };
        // SAFETY: the allocation reserves `length + 1` bytes, including this
        // following output position or its final terminator position.
        output = unsafe { output.add(1) };
        remaining -= 1;
    }
    // SAFETY: the allocation's final byte remains reserved for this terminator.
    unsafe { output.write(0) };
    destination.cast::<c_char>()
}

/// Duplicate one complete caller-owned C string.
///
/// # Safety
///
/// `source` must designate a readable NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn strdup(source: *const c_char) -> *mut c_char {
    let mut cursor = source.cast::<u8>();
    let mut length = 0usize;
    loop {
        // SAFETY: the C-string contract supplies this current byte.
        if unsafe { cursor.read() } == 0 {
            // SAFETY: the scan proved this exact readable prefix length.
            return unsafe { duplicate_prefix(source.cast::<u8>(), length) };
        }
        // SAFETY: the observed non-NUL byte proves the following C-string byte.
        cursor = unsafe { cursor.add(1) };
        let Some(next_length) = length.checked_add(1) else {
            // SAFETY: this is the selected C ABI's one calling-thread errno slot.
            unsafe { errno::set_errno(ENOMEM) };
            return core::ptr::null_mut();
        };
        length = next_length;
    }
}

/// Duplicate at most `limit` bytes and always append one NUL terminator.
///
/// # Safety
///
/// If `limit` is nonzero, `source` must designate readable bytes through its
/// first NUL or through the complete `limit` range. The caller retains the C
/// API's pointer-validity obligation even when a zero limit performs no read.
#[no_mangle]
pub unsafe extern "C" fn strndup(source: *const c_char, limit: usize) -> *mut c_char {
    let mut cursor = source.cast::<u8>();
    let mut length = 0usize;
    while length != limit {
        // SAFETY: `length < limit` retains one readable input byte.
        if unsafe { cursor.read() } == 0 {
            break;
        }
        // SAFETY: the observed non-NUL byte lies inside the caller's retained
        // bounded range, so the following iteration's byte exists only while
        // `length` remains below `limit`.
        cursor = unsafe { cursor.add(1) };
        length += 1;
    }
    // SAFETY: the bounded scan established exactly `length` readable bytes.
    unsafe { duplicate_prefix(source.cast::<u8>(), length) }
}

/// Link-time witness for the opt-in x86 string-duplication object.
///
/// This private evidence glue forces the client object into its mixed-runtime
/// candidate before the link map verifies that musl supplies neither duplicate
/// entry nor an allocator implementation.
#[no_mangle]
pub extern "C" fn __crabc_x86_allocator_string_duplication_v1() -> usize {
    1
}
