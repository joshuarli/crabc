//! Owned byte scanf: pinned grammar, numerical conversion and allocation.
//!
//! `owned_scanf_musl_x86_64.S` translates musl 1.2.6 release commit
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417 (MIT; full license in assembly).
//! The digest-checked `compat/x86_64/generate_owned_scanf.py` maps
//! `src/stdio/vfscanf.c` to the byte grammar, positional pointer arguments,
//! widths, suppression, count stores, scansets and malloc/realloc cleanup;
//! `src/internal/{intscan,floatscan}.c` to integer and binary32/64/80 parsing;
//! and `src/internal/shgetc.{h,c}` to field limits and consumed-byte accounting.
//! Numerical algorithms and x87 rounding/fenv operations are unchanged.
//! The normal product build includes fixed assembly, not foreign C objects.
//!
//! Intentional adapters: the private cursor contains only scanner fields and
//! obtains one byte synchronously from an owned source. It is not public FILE
//! storage. scanf uses pok=0, so only one delimiter needs restoring. Rust
//! holds the real FILE's lock across admission, every read, allocation and
//! final lookahead restoration; no cursor or callback pointer escapes. The
//! string path shares the same grammar and stops before its NUL terminator.
//! Wide character destinations use the retained upstream mbrtowc/mbstate_t
//! branch and the same allocation cleanup. Wide-format scanf is a separate
//! entry/parser; this is not a complete stdio-family claim. The existing
//! strto* scanner's private callback contract remains untouched.

use super::*;
use core::ffi::c_void;

core::arch::global_asm!(include_str!("owned_scanf_musl_x86_64.S"), options(att_syntax));

unsafe extern "C" {
    fn __crabc_owned_scan(context: *mut c_void,
        get: unsafe extern "C" fn(*mut c_void) -> c_int,
        unget: unsafe extern "C" fn(*mut c_void, c_int),
        format: *const c_char, arguments: *mut VaList<'_>) -> c_int;
}

unsafe extern "C" fn string_get(context: *mut c_void) -> c_int {
    unsafe {
        let cursor = &mut *context.cast::<*const u8>();
        let byte = (*cursor).read();
        if byte == 0 { return EOF; }
        *cursor = (*cursor).add(1);
        byte as c_int
    }
}

unsafe extern "C" fn string_unget(context: *mut c_void, _byte: c_int) {
    unsafe {
        let cursor = &mut *context.cast::<*const u8>();
        *cursor = (*cursor).sub(1);
    }
}

unsafe extern "C" fn stream_get(context: *mut c_void) -> c_int {
    unsafe { stdio_standard::read_scanned_byte(context.cast()) }
}

unsafe extern "C" fn stream_unget(context: *mut c_void, byte: c_int) {
    unsafe { stdio_standard::ungetc(byte, context.cast()); }
}

// Public sscanf/vsscanf callers supply NUL-terminated strings and correctly
// typed, writable non-suppressed destinations, including char** for %m.
pub(super) unsafe fn string(input: *const c_char, format: *const c_char, args: &mut VaList<'_>) -> c_int {
    unsafe {
        let mut cursor = input.cast::<u8>();
        __crabc_owned_scan((&mut cursor as *mut *const u8).cast(), string_get, string_unget, format, args)
    }
}

// A live FILE cannot be destroyed concurrently. Its scoped guard survives
// all C callbacks and upstream %m cleanup, including every failure return.
pub(super) unsafe fn stream(stream: *mut StandardStream, format: *const c_char, args: &mut VaList<'_>) -> c_int {
    unsafe {
        stdio_standard::with_scanned_stream(stream, || {
            __crabc_owned_scan(stream.cast(), stream_get, stream_unget, format, args)
        })
    }
}
