//! Static Linux/x86-64 C11 immediate-termination boundary.
//!
//! This leaf owns exactly C11 [`_Exit`]: immediate whole-process termination
//! through Linux `exit_group`. It has no return value, writable caller state,
//! errno result, allocator, callback registry, or runtime lock. It does not establish
//! POSIX `_exit`, `exit`, `abort`, `atexit`, `at_quick_exit`,
//! `quick_exit`, stdio flushing, fini/destructor processing, fork
//! coordination, pthread lifecycle, a dynamic libc, CRT, loader, sysroot,
//! allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/exit/_Exit.c` issues `SYS_exit_group` and defensively loops through
//! `SYS_exit` only if the whole-process path returns. This leaf preserves that
//! exact no-return fallback without acquiring musl's ordinary-exit or
//! quick-exit hook state.

use core::ffi::c_int;

use super::raw_syscall;

/// Immediately terminate the calling process with `status`.
///
/// Linux's `exit_group` normally terminates every thread and never returns.
/// If an unusual execution environment returns from it, retain musl's
/// defensive `exit` retry loop rather than report a fabricated errno result.
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn _Exit(status: c_int) -> ! {
    // SAFETY: both syscalls take one scalar exit-status word. `exit_group`
    // normally terminates the whole process; a returning result is discarded
    // so the defensive thread-exit loop below retains musl's no-return
    // contract.
    unsafe {
        let _ = raw_syscall::syscall1(raw_syscall::SYS_EXIT_GROUP, i64::from(status));
        loop {
            let _ = raw_syscall::syscall1(raw_syscall::SYS_EXIT, i64::from(status));
        }
    }
}
