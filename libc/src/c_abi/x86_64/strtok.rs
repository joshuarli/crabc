//! Linux/x86-64 selected static C `strtok` compatibility leaf.
//!
//! Provenance is fixed to musl 1.2.6
//! (`9fa28ece75d8a2191de7c5bb53bed224c5947417`) under musl's MIT license
//! recorded in its `COPYRIGHT` file. The exact public source is
//! `src/string/strtok.c`: a process-global continuation pointer is selected
//! when the input is null; musl skips the leading delimiter span, finds the
//! next delimiter span, replaces one selected delimiter with NUL, and stores
//! the following byte as the continuation.
//!
//! The span scans remain local to this target-private leaf. That preserves the
//! source behavior without selecting another static archive member or the
//! separate reentrant tokenizer ABI. `CONTINUATION` deliberately is one shared
//! non-TLS cursor, matching musl's historical C contract: a non-null input
//! replaces it, interleaved sequences overwrite it, and concurrent
//! unsynchronized calls are outside the defined C contract. It is not a
//! thread-safe tokenizer or a Rust-facing text API.
//!
//! This is a private selected static artifact, not general string/tokenizer
//! support, libc.so, a CRT, loader, sysroot, or public x86 support claim.

use core::{ffi::c_char, ptr::null_mut};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 C strtok leaf requires little-endian Linux/x86-64");

// Musl's `static char *p` is one process-global continuation cursor. It is
// intentionally not TLS or an atomic synchronization mechanism.
static mut CONTINUATION: *mut c_char = null_mut();

/// Return whether `byte` occurs before the NUL terminator of `separators`.
///
/// # Safety
///
/// `separators` must designate a readable NUL-terminated byte sequence.
#[inline]
unsafe fn is_separator(mut separators: *const u8, byte: u8) -> bool {
    loop {
        // SAFETY: the helper contract supplies this C-string byte.
        let separator = unsafe { separators.read() };
        if separator == byte {
            return true;
        }
        if separator == 0 {
            return false;
        }
        // SAFETY: a non-NUL separator proves the next C-string byte exists.
        separators = unsafe { separators.add(1) };
    }
}

/// Skip the initial delimiter run, matching musl's local leading-span step.
///
/// # Safety
///
/// `cursor` and `separators` must designate readable NUL-terminated byte
/// sequences. `cursor` is mutable because the public leaf may later split it.
#[inline]
unsafe fn skip_separators(mut cursor: *mut u8, separators: *const u8) -> *mut u8 {
    loop {
        // SAFETY: the helper contract supplies this C-string byte.
        let byte = unsafe { cursor.read() };
        if byte == 0 || !unsafe { is_separator(separators, byte) } {
            return cursor;
        }
        // SAFETY: a non-NUL byte proves the following C-string byte exists.
        cursor = unsafe { cursor.add(1) };
    }
}

/// Find the first delimiter or terminator after a token start.
///
/// # Safety
///
/// `cursor` and `separators` must designate readable NUL-terminated byte
/// sequences.
#[inline]
unsafe fn token_end(mut cursor: *mut u8, separators: *const u8) -> *mut u8 {
    loop {
        // SAFETY: the helper contract supplies this C-string byte.
        let byte = unsafe { cursor.read() };
        if byte == 0 || unsafe { is_separator(separators, byte) } {
            return cursor;
        }
        // SAFETY: a non-NUL byte proves the following C-string byte exists.
        cursor = unsafe { cursor.add(1) };
    }
}

/// Split a mutable C string into the next nonempty delimiter-delimited token.
///
/// A non-null `string` begins (or replaces) the one process-global sequence.
/// A null `string` resumes its shared continuation. Exhaustion clears that
/// continuation. The token and delimiter pointers must satisfy the C
/// declaration's `restrict` non-aliasing contract.
///
/// # Safety
///
/// `separators` must designate a readable NUL-terminated C string. A non-null
/// `string` (or the stored continuation for a null `string`) must designate a
/// writable NUL-terminated C string. This entry may write one NUL byte to that
/// caller-owned input. Invalid pointers, unterminated strings, concurrent
/// unsynchronized calls, and violations of the C `restrict` obligations are
/// outside this compatibility leaf's contract.
#[no_mangle]
pub unsafe extern "C" fn strtok(
    string: *mut c_char,
    separators: *const c_char,
) -> *mut c_char {
    let mut cursor = if string.is_null() {
        // SAFETY: this is the intentionally shared musl-compatible cursor.
        unsafe { CONTINUATION }
    } else {
        string
    }
    .cast::<u8>();
    let separators = separators.cast::<u8>();

    if cursor.is_null() {
        return null_mut();
    }

    // SAFETY: the public C contract supplies both terminated byte sequences.
    cursor = unsafe { skip_separators(cursor, separators) };
    // SAFETY: the span scan returns a readable byte in that C string.
    if unsafe { cursor.read() } == 0 {
        // SAFETY: only this historical global cursor is changed.
        unsafe { CONTINUATION = null_mut() };
        return null_mut();
    }

    let token = cursor;
    // SAFETY: `token` begins a nonempty mutable C string under the contract.
    cursor = unsafe { token_end(cursor, separators) };
    // SAFETY: the scan returns a delimiter byte or the terminator.
    if unsafe { cursor.read() } == 0 {
        // SAFETY: only this historical global cursor is changed.
        unsafe { CONTINUATION = null_mut() };
    } else {
        // SAFETY: this is a selected non-NUL delimiter in caller-owned input;
        // its following byte exists, and only the shared cursor is updated.
        unsafe {
            cursor.write(0);
            CONTINUATION = cursor.add(1).cast::<c_char>();
        }
    }

    token.cast::<c_char>()
}
