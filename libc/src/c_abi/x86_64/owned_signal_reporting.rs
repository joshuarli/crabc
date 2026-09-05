//! Owned psignal/psiginfo, translated from musl 1.2.6 (MIT), release revision
//! 9fa28ece75d8a2191de7c5bb53bed224c5947417, src/signal/{psignal,psiginfo}.c.
//! The FILE owner retains the outer lock and restores orientation plus its
//! C/POSIX versus C.UTF-8 encoding snapshot around one ordinary fprintf call.
//! The existing formatter owns musl's temporary 80-byte unbuffered adapter,
//! so partial writes are not replaced by independently written string pieces.

use core::ffi::{c_char, c_int, c_void};
use super::{errno, StreamGuard};

/// Print a signal description without changing stderr's orientation/encoding.
///
/// # Safety
/// A non-null message is readable through its terminating NUL. The caller
/// obeys ordinary stderr lifetime rules. This function locks FILE state and
/// is not async-signal-safe; do not call it from a signal handler.
#[no_mangle]
pub unsafe extern "C" fn psignal(signal: c_int, message: *const c_char) {
    unsafe {
        let stream = super::stderr;
        let description = super::super::strsignal::strsignal(signal);
        let _guard = StreamGuard::acquire(stream);
        let old_orientation = (*stream).orientation;
        let old_locale = (*stream).wide_locale;
        let old_errno = errno::get_errno();
        let prefix = if message.is_null() { c"".as_ptr() } else { message };
        let separator = if message.is_null() { c"".as_ptr() } else { c": ".as_ptr() };
        if super::super::stdio_format_scan::fprintf(stream, c"%s%s%s\n".as_ptr(),
            prefix, separator, description) >= 0 {
            errno::set_errno(old_errno);
        }
        (*stream).orientation = old_orientation;
        (*stream).wide_locale = old_locale;
    }
}

#[repr(C)]
struct SigInfoPrefix { signal: c_int }

/// Print the signal number at the beginning of a caller-owned siginfo record.
///
/// # Safety
/// `information` points to a readable siginfo_t, including its first si_signo
/// field. Message and asynchronous-call obligations are those of psignal.
#[no_mangle]
pub unsafe extern "C" fn psiginfo(information: *const c_void, message: *const c_char) {
    unsafe { psignal((*information.cast::<SigInfoPrefix>()).signal, message) };
}
