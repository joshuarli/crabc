//! Bounded static Linux/x86-64 `psignal` and `psiginfo` C ABI boundary.
//!
//! This opt-in leaf maps pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` (musl MIT) directly:
//!
//! - `src/signal/psignal.c` supplies the `msg ? "msg: " : ""`,
//!   `strsignal`, trailing-newline, and successful-output-only `errno`
//!   restoration contract.
//! - `src/signal/psiginfo.c` supplies the exact `si_signo` forwarding body.
//!
//! The feature composes only the existing x86 fixed-description `strsignal`,
//! permanent `stderr` output, and initial-TLS `errno` owner.  It performs no
//! locale/catalog lookup, formatting parser, allocation, process signal
//! delivery/disposition operation, or general diagnostics promotion.
//!
//! Musl locks its full `FILE` around `fprintf` and restores that full FILE's
//! locale/orientation fields after the call.  The selected x86 permanent-stream
//! artifact deliberately has no general FILE lock, locale, or orientation
//! state; its contract instead requires external serialization of permanent
//! stream access.  This leaf keeps that narrower pre-existing boundary: callers
//! must serialize a `psignal`/`psiginfo` call with every other selected use of
//! `stderr`.  Within that boundary, its unbuffered permanent stderr route
//! preserves musl's complete-output bytes and success-only errno rule. It
//! intentionally does not claim musl's private 80-byte `vfprintf` buffering
//! or its nonblocking short-write prefix behavior: adding that would expand
//! the selected permanent-stream core into a general formatted-stdio owner.
//! The focused evidence therefore covers complete output plus first-write
//! `EAGAIN`/`EBADF` failures, not partial-output equivalence.
//! It is not async-signal-safe: a signal handler must not reenter this selected
//! permanent-stream state.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 static signal-reporting leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int, c_void};

use super::{
    errno,
    stdio_standard::{self, StandardStream},
    strsignal,
};

/// The only `siginfo_t` field that pinned musl's `psiginfo` observes.
///
/// Linux/x86-64's public record begins with `int si_signo`; the surrounding
/// record remains caller-owned and is neither copied nor validated by musl.
#[repr(C)]
struct SigInfoPrefix {
    signal: c_int,
}

/// Obtain the selected permanent stderr object without accepting a caller
/// supplied `FILE *` or widening the permanent-stream boundary.
#[inline]
unsafe fn permanent_stderr() -> *mut StandardStream {
    // SAFETY: `stderr` is the process-lifetime selected permanent stream data
    // object owned by `stdio_standard`; reading its pointer cannot move it.
    unsafe { stdio_standard::stderr }
}

/// Emit one NUL-terminated C string through the selected permanent stderr.
///
/// A negative result records the existing permanent-stream write failure in
/// the selected initial-TLS errno slot.  The caller decides whether a complete
/// reporting transaction succeeded and may restore its incoming errno only in
/// that case.
#[inline]
unsafe fn write_stderr_string(source: *const c_char, stream: *mut StandardStream) -> bool {
    // SAFETY: the caller supplies a readable NUL-terminated C string, and the
    // stream is exactly the permanent `stderr` object above.
    unsafe { stdio_standard::fputs(source, stream) >= 0 }
}

/// Emit one trailing newline through the selected permanent stderr.
#[inline]
unsafe fn write_stderr_newline(stream: *mut StandardStream) -> bool {
    // SAFETY: the stream is exactly the selected permanent stderr object.
    unsafe { stdio_standard::fputc(c_int::from(b'\n'), stream) >= 0 }
}

/// Print one signal description to the selected permanent stderr.
///
/// # Safety
///
/// If non-null, `message` must point to a readable NUL-terminated C string
/// for the duration of this call. Callers must externally serialize this call
/// with every selected use of `stderr`; the bounded permanent-stream substrate
/// deliberately does not own musl's general FILE locking/locale/orientation
/// state. It is not async-signal-safe and must not run from a signal handler.
/// On complete output this preserves the incoming C `errno`; on a
/// failed output it leaves the permanent-stream error (for example `EBADF`) in
/// `errno`, matching musl's success-only restoration rule.
#[no_mangle]
pub unsafe extern "C" fn psignal(signal: c_int, message: *const c_char) {
    // SAFETY: this feature owns the calling thread's selected errno slot.
    let saved_errno = unsafe { errno::get_errno() };
    // SAFETY: this helper returns only the permanent process-lifetime stderr.
    let stream = unsafe { permanent_stderr() };
    let mut complete = true;

    if !message.is_null() {
        // SAFETY: `message` meets this public C entry point's string contract.
        complete = unsafe { write_stderr_string(message, stream) };
        if complete {
            // SAFETY: this is one immutable NUL-terminated literal.
            complete = unsafe {
                write_stderr_string(b": \0".as_ptr().cast::<c_char>(), stream)
            };
        }
    }
    if complete {
        // SAFETY: `strsignal` owns its immutable process-static return string.
        let description = strsignal::strsignal(signal);
        // SAFETY: `description` is a readable NUL-terminated static string.
        complete = unsafe { write_stderr_string(description, stream) };
    }
    if complete {
        // SAFETY: permanent stderr accepts one selected unbuffered byte.
        complete = unsafe { write_stderr_newline(stream) };
    }

    if complete {
        // Musl restores errno only when the entire formatted output succeeds.
        // SAFETY: this feature owns the calling thread's selected errno slot.
        unsafe { errno::set_errno(saved_errno) };
    }
}

/// Report the signal number stored at the beginning of one caller-owned
/// Linux/x86-64 `siginfo_t` record.
///
/// # Safety
///
/// `information` must point to a readable `siginfo_t` whose first field is a
/// valid `int si_signo`; null/invalid input has the same undefined behavior as
/// musl's direct `si->si_signo` dereference. `message` and stderr
/// serialization have the same requirements as [`psignal`].
#[no_mangle]
pub unsafe extern "C" fn psiginfo(information: *const c_void, message: *const c_char) {
    // SAFETY: the caller supplies the same complete `siginfo_t` prefix musl
    // dereferences directly. `SigInfoPrefix` anchors only that observed field.
    let signal = unsafe { (*information.cast::<SigInfoPrefix>()).signal };
    // SAFETY: `message` and the permanent stderr serialization obligation pass
    // through unchanged to the selected psignal boundary.
    unsafe { psignal(signal, message) };
}
