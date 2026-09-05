//! Owned Linux/x86-64 C diagnostic reporting, translated from musl 1.2.6.
//!
//! Pinned musl release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`
//! (MIT; source archive SHA-256
//! `d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`)
//! maps `src/stdio/perror.c` to [`perror`] and `src/legacy/err.c` to the
//! `warn`/`err` family below.  The functions deliberately retain musl's
//! public C call edges: `perror` reaches `strerror`, warning records reach
//! `fprintf`, `vfprintf`, `fputs`, `putc`, and `perror`, and the terminating
//! forms route through `vwarn`/`vwarnx` and `exit`.  Those declarations are
//! kept in [`source`] rather than replaced with private Rust calls so an ELF
//! final link retains the same source-level provider resolution boundary.
//!
//! `perror.c` obtains `strerror(errno)` before it locks `stderr`, then saves
//! and restores FILE orientation and the captured wide conversion locale.
//! The latter restoration matters even though the selected stderr normally
//! begins unoriented.  `err.c` deliberately has no outer FILE transaction:
//! each public stdio call acquires its own recursive guard, so concurrent
//! warning calls may interleave at those source-call boundaries.  The normal
//! `err` forms deliberately use ordinary `exit`, preserving registered exit
//! handlers and buffered-stream finalization.
//!
//! This is a source-bound C diagnostic interface.  It does not select a
//! message catalog, locale database, arbitrary FILE ABI, asynchronous signal
//! reporting, a separate process-termination owner, or a general logging
//! subsystem.  Like the source routines, callers must provide valid C strings
//! and matching variadic arguments; all output error handling remains the
//! selected stdio engine's responsibility.

use core::ffi::{c_char, c_int, c_void, VaList};

use super::{stderr, StreamGuard, StandardStream};

/// Namespaced declarations preserve the public source-call graph without
/// importing sibling Rust implementations by a private path.  In particular,
/// references remain ordinary strong C symbols. The owned static archive's
/// single code-generation unit limits application replacement of individual
/// providers, as recorded in `compat/x86_64/owned-error-reporting.md`. In a
/// shared libc these edges bind locally, matching pinned musl, while external
/// consumers retain ordinary public ELF lookup.
mod source {
    use core::ffi::{c_char, c_int, c_void, VaList};

    use super::StandardStream;

    unsafe extern "C" {
        pub(super) static mut __progname: *mut c_char;
        pub(super) fn strerror(error: c_int) -> *mut c_char;
        pub(super) fn fprintf(
            stream: *mut StandardStream,
            format: *const c_char,
            ...,
        ) -> c_int;
        pub(super) fn vfprintf(
            stream: *mut StandardStream,
            format: *const c_char,
            arguments: VaList<'_>,
        ) -> c_int;
        pub(super) fn fputs(string: *const c_char, stream: *mut StandardStream) -> c_int;
        pub(super) fn putc(character: c_int, stream: *mut StandardStream) -> c_int;
        pub(super) fn fputc(character: c_int, stream: *mut StandardStream) -> c_int;
        pub(super) fn fwrite(
            source: *const c_void,
            size: usize,
            count: usize,
            stream: *mut StandardStream,
        ) -> usize;
        pub(super) fn perror(message: *const c_char);
        pub(super) fn vwarn(format: *const c_char, arguments: VaList<'_>);
        pub(super) fn vwarnx(format: *const c_char, arguments: VaList<'_>);
        pub(super) fn verr(status: c_int, format: *const c_char, arguments: VaList<'_>) -> !;
        pub(super) fn verrx(status: c_int, format: *const c_char, arguments: VaList<'_>) -> !;
        pub(super) fn exit(status: c_int) -> !;
    }
}

const PREFIX_FORMAT: &[u8] = b"%s: \0";
const ERROR_SEPARATOR: &[u8] = b": \0";

/// Emit `perror.c`'s saved message under one stderr lock and restore its
/// orientation state on every normal return.
unsafe fn emit_perror(message: *const c_char, error_message: *const c_char) {
    // SAFETY: `stderr` remains the process-lifetime selected stream.  The
    // source operation itself admits only valid C strings, as this boundary
    // documents for its public caller below.
    unsafe {
        let stream = stderr;
        let _guard = StreamGuard::acquire(stream);
        let old_orientation = (*stream).orientation;
        let old_wide_locale = (*stream).wide_locale;

        if !message.is_null() && *message != 0 {
            // This is `fwrite(msg, strlen(msg), 1, f)` from perror.c.  The
            // direct selected strlen avoids expanding this diagnostic leaf's
            // public call surface; the visible output calls remain source
            // edges in `source`.
            let length = super::super::byte_strings::strlen(message);
            let _ = source::fwrite(message.cast::<c_void>(), length, 1, stream);
            let _ = source::fputc(c_int::from(b':'), stream);
            let _ = source::fputc(c_int::from(b' '), stream);
        }
        let error_length = super::super::byte_strings::strlen(error_message);
        let _ = source::fwrite(error_message.cast::<c_void>(), error_length, 1, stream);
        let _ = source::fputc(c_int::from(b'\n'), stream);

        // perror.c restores both fields while still holding FLOCK(f).  The
        // guard then releases this one operation's outer lock.
        (*stream).orientation = old_orientation;
        (*stream).wide_locale = old_wide_locale;
    }
}

/// Report the current errno through the selected permanent stderr stream.
///
/// # Safety
/// If non-null, `message` must designate a readable NUL-terminated C string
/// for the duration of the call.  The current thread must have initialized
/// selected errno and owned standard-stream state.  This routine is not
/// async-signal-safe.
#[no_mangle]
pub unsafe extern "C" fn perror(message: *const c_char) {
    // perror.c deliberately asks strerror before FLOCK(stderr).  Preserve a
    // final-link source edge here rather than reading the private fixed table.
    let error_message = unsafe { source::strerror(super::super::errno::get_errno()) };
    // SAFETY: source strerror supplies a NUL-terminated message for the
    // admitted errno domain; its caller string obligation passes through.
    unsafe { emit_perror(message, error_message) };
}

/// Report one errno-bearing formatted diagnostic under the current program
/// name.
///
/// # Safety
/// `format` may be null, as in musl.  Otherwise it must be a readable
/// NUL-terminated format string and `arguments` must hold its matching
/// promoted values.  The initialized current task owns the selected errno and
/// stdout/stderr runtime state.  This routine is not async-signal-safe.
#[no_mangle]
pub unsafe extern "C" fn vwarn(format: *const c_char, arguments: VaList<'_>) {
    unsafe {
        let stream = stderr;
        // err.c has no outer FLOCK: preserve its public source-edge sequence
        // and let each selected stdio operation retain its own lock boundary.
        let _ = source::fprintf(stream, PREFIX_FORMAT.as_ptr().cast(), source::__progname);
        if !format.is_null() {
            let _ = source::vfprintf(stream, format, arguments);
            let _ = source::fputs(ERROR_SEPARATOR.as_ptr().cast(), stream);
        }
        source::perror(core::ptr::null());
    }
}

/// Report one non-errno formatted diagnostic under the current program name.
///
/// # Safety
/// `format` may be null, as in musl.  Otherwise it must be a readable
/// NUL-terminated format string and `arguments` must hold its matching
/// promoted values.  The initialized current task owns the selected stderr
/// runtime state.  This routine is not async-signal-safe.
#[no_mangle]
pub unsafe extern "C" fn vwarnx(format: *const c_char, arguments: VaList<'_>) {
    unsafe {
        let stream = stderr;
        // err.c has no outer FLOCK: preserve its public source-edge sequence
        // and let each selected stdio operation retain its own lock boundary.
        let _ = source::fprintf(stream, PREFIX_FORMAT.as_ptr().cast(), source::__progname);
        if !format.is_null() {
            let _ = source::vfprintf(stream, format, arguments);
        }
        let _ = source::putc(c_int::from(b'\n'), stream);
    }
}

/// C-variadic entry point forwarding to musl's public `vwarn` edge.
///
/// # Safety
/// `format` and its promoted variadic values satisfy [`vwarn`]'s contract.
/// The current task has initialized selected errno and stderr state.
#[no_mangle]
pub unsafe extern "C" fn warn(format: *const c_char, arguments: ...) {
    unsafe { source::vwarn(format, arguments) };
}

/// C-variadic entry point forwarding to musl's public `vwarnx` edge.
///
/// # Safety
/// `format` and its promoted variadic values satisfy [`vwarnx`]'s contract.
/// The current task has initialized selected stderr state.
#[no_mangle]
pub unsafe extern "C" fn warnx(format: *const c_char, arguments: ...) {
    unsafe { source::vwarnx(format, arguments) };
}

/// Emit an errno-bearing diagnostic and then perform ordinary process exit.
///
/// # Safety
/// `format` and `arguments` satisfy [`vwarn`]'s contract.  This function does
/// not return and runs the selected ordinary-exit callbacks and stdio flush.
#[no_mangle]
pub unsafe extern "C" fn verr(status: c_int, format: *const c_char, arguments: VaList<'_>) -> ! {
    unsafe {
        source::vwarn(format, arguments);
        source::exit(status)
    }
}

/// Emit a non-errno diagnostic and then perform ordinary process exit.
///
/// # Safety
/// `format` and `arguments` satisfy [`vwarnx`]'s contract.  This function
/// does not return and runs the selected ordinary-exit callbacks and stdio
/// flush.
#[no_mangle]
pub unsafe extern "C" fn verrx(status: c_int, format: *const c_char, arguments: VaList<'_>) -> ! {
    unsafe {
        source::vwarnx(format, arguments);
        source::exit(status)
    }
}

/// C-variadic entry point forwarding to musl's public `verr` edge.
///
/// # Safety
/// `format` and its promoted variadic values satisfy [`verr`]'s contract.
/// This function does not return.
#[no_mangle]
pub unsafe extern "C" fn err(status: c_int, format: *const c_char, arguments: ...) -> ! {
    unsafe { source::verr(status, format, arguments) }
}

/// C-variadic entry point forwarding to musl's public `verrx` edge.
///
/// # Safety
/// `format` and its promoted variadic values satisfy [`verrx`]'s contract.
/// This function does not return.
#[no_mangle]
pub unsafe extern "C" fn errx(status: c_int, format: *const c_char, arguments: ...) -> ! {
    unsafe { source::verrx(status, format, arguments) }
}
