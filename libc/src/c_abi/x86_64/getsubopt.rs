//! State-free Linux/x86-64 C `getsubopt` parser.
//!
//! This leaf owns exactly the in-place comma-delimited suboption parser from
//! pinned musl 1.2.6.  It consumes one token from the caller-owned mutable
//! string, replaces one separating comma with NUL when present, advances the
//! caller's cursor, clears the caller's value pointer, and returns the first
//! exact key match or `-1`.  A key matches only when the following input byte
//! is NUL or `=`; the latter returns the bytes after `=` through `value`.
//!
//! The C ABI requires valid readable/writable input pointers, a NUL-terminated
//! key vector, and writable cursor/value slots.  As in musl, invalid pointers
//! are outside this leaf's contract rather than translated into an errno
//! result.  The parser owns no storage and reads or writes no errno, TLS,
//! locale, environment, allocator, stdio, syscall, or process state.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/misc/getsubopt.c` maps directly to [`getsubopt`].  Its `strchr`,
//! `strlen`, and `strncmp` calls are represented by the corresponding local
//! byte walks so the selected archive member has no ambient libc dependency.

use core::ffi::{c_char, c_int};

/// Consume one caller-owned suboption and return its first matching key index.
///
/// The caller must provide the valid pointer and NUL-termination obligations
/// documented by C's `getsubopt` interface.  The input string is modified in
/// place exactly at the first comma in the consumed token.
#[no_mangle]
pub unsafe extern "C" fn getsubopt(
    option: *mut *mut c_char,
    keys: *const *mut c_char,
    value: *mut *mut c_char,
) -> c_int {
    // SAFETY: the C caller supplies writable cursor/value slots and a valid
    // NUL-terminated mutable option string, matching musl's direct dereference
    // contract.
    let start = unsafe { core::ptr::read(option) };
    // SAFETY: `value` is a valid writable caller slot under the same contract.
    unsafe { core::ptr::write(value, core::ptr::null_mut()) };

    let mut end = start;
    let mut token_len = 0usize;
    // SAFETY: the caller's option string is NUL terminated and readable until
    // that terminator, so this walk remains inside its supplied object.
    while unsafe { core::ptr::read(end) } != 0 && unsafe { core::ptr::read(end) } != b',' as c_char {
        // SAFETY: the preceding read was not the NUL terminator.
        end = unsafe { end.add(1) };
        token_len += 1;
    }

    // SAFETY: `end` points at either the token's comma or its NUL terminator.
    if unsafe { core::ptr::read(end) } == b',' as c_char {
        // SAFETY: a comma belongs to the mutable caller-owned option string.
        unsafe { core::ptr::write(end, 0) };
        // SAFETY: one byte after that comma remains within the caller's
        // NUL-terminated option string.
        unsafe { core::ptr::write(option, end.add(1)) };
    } else {
        // SAFETY: the cursor may point at the final NUL after its final token.
        unsafe { core::ptr::write(option, end) };
    }

    let mut key_index = 0usize;
    loop {
        // SAFETY: the caller supplies a NUL-terminated key vector, like musl.
        let key = unsafe { core::ptr::read(keys.add(key_index)) };
        if key.is_null() {
            return -1;
        }

        let mut key_len = 0usize;
        // SAFETY: every non-null key vector entry is a readable NUL-terminated
        // C string under the caller contract.
        // Keep this as the source-level byte walk rather than allowing the
        // optimizer to select the separately owned `strlen` archive leaf.
        while core::hint::black_box(unsafe { core::ptr::read(key.add(key_len)) }) != 0 {
            key_len += 1;
        }

        let mut matches = true;
        for offset in 0..key_len {
            // `strncmp` stops when the token terminates.  Keeping that
            // boundary explicit avoids reading past the caller's current
            // token when a key is longer than it.
            if offset == token_len {
                matches = false;
                break;
            }
            // SAFETY: the key and current token are readable until their NUL
            // terminators.  This is the same bounded byte comparison as musl's
            // `strncmp(keys[i], s, key_len)`.
            if unsafe { core::ptr::read(key.add(offset)) }
                != unsafe { core::ptr::read(start.add(offset)) }
            {
                matches = false;
                break;
            }
        }

        if matches {
            // SAFETY: `start + key_len` is the exact suffix byte inspected by
            // musl after the successful prefix comparison.
            let suffix = unsafe { core::ptr::read(start.add(key_len)) };
            if suffix == b'=' as c_char {
                // SAFETY: the suffix is inside the current caller-owned token.
                unsafe { core::ptr::write(value, start.add(key_len + 1)) };
                return key_index as c_int;
            }
            if suffix == 0 {
                return key_index as c_int;
            }
        }

        key_index += 1;
    }
}
