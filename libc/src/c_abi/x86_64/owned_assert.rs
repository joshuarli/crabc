//! Installed C assertion failure, translated from musl 1.2.6 `src/exit/assert.c`.
//!
//! Pinned release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under
//! musl's MIT license in `COPYRIGHT`, owns the diagnostic format and the
//! `fprintf(stderr, ...)` then `abort()` sequence. The owned FILE engine
//! supplies musl's unbuffered default stderr. Preserve an application's
//! explicit buffering choices; this entry does not add an exit flush or run
//! ordinary exit handlers. The frozen private archive and AArch64 assertion
//! implementation remain separate.

use core::ffi::{c_char, c_int};

use super::{owned_static_abort, stdio_format_scan, stdio_standard};

/// Report the failed C assertion and terminate through the owned abort path.
///
/// # Safety
/// `expression`, `file`, and `function` must each remain readable through a
/// terminating NUL. The current process must have initialized the owned FILE
/// and signal runtime. This operation does not return.
#[no_mangle]
pub unsafe extern "C" fn __assert_fail(
    expression: *const c_char,
    file: *const c_char,
    line: c_int,
    function: *const c_char,
) -> ! {
    // SAFETY: the fixed format consumes exactly three caller strings and the
    // native int line number; stderr is the runtime's live standard stream.
    unsafe {
        stdio_format_scan::fprintf(
            stdio_standard::stderr,
            b"Assertion failed: %s (%s: %s: %d)\n\0".as_ptr().cast(),
            expression,
            file,
            function,
            line,
        );
    }
    owned_static_abort::abort()
}
