//! Private Linux/x86-64 direct process-image replacement boundary.
//!
//! This opt-in leaf owns only `execve` and `fexecve`. It composes the selected
//! x86 raw syscall instruction boundary and initial-TLS `errno`; it does not
//! read `__environ`, search `PATH`, inspect C varargs, allocate an argv vector,
//! or select fork, vfork, clone, posix_spawn, cancellation, signal-mask
//! policy, child reaping, a general C runtime, libc.so, CRT, loader, sysroot,
//! allocator runtime, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/process/execve.c` maps to [`execve`], and `src/process/fexecve.c`
//! maps to [`fexecve`]'s direct `execveat(fd, "", argv, envp,
//! AT_EMPTY_PATH)` path.
//!
//! Musl falls back to `/proc/self/fd` only if `execveat` reports `ENOSYS`.
//! The project baseline is Linux 5.10, where x86-64 `execveat=322` is
//! available, so this leaf deliberately exposes that `ENOSYS` (including a
//! seccomp-produced one) through `errno`: it neither forms a procfd pathname
//! nor applies musl's fallback-only `ENOENT` to `EBADF` remapping.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 direct exec leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int};

use super::{c_status, raw_syscall};

const AT_EMPTY_PATH: i64 = 0x1000;
const EMPTY_PATH: [u8; 1] = [0];

/// Invoke Linux `execve` and translate its raw error result through the
/// selected initial-TLS errno boundary.
///
/// This stays in the direct archive member so the PATH/environment/vararg
/// siblings can depend on the one raw C ABI translation without making a
/// direct `execve` or `fexecve` consumer extract their wider closures.
#[inline(never)]
pub(super) unsafe fn execve_result(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    // SAFETY: the C caller owns Linux's pathname, argv, and envp pointer
    // contracts through this direct process-image replacement boundary.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_EXECVE,
            path as usize as i64,
            argv as usize as i64,
            envp as usize as i64,
        )
    };
    c_status(result)
}

/// Replace the current image with `path`, `argv`, and the supplied `envp`.
///
/// C callers must supply Linux-valid null-terminated pathname, argv, and envp
/// objects for the duration of the syscall. A successful call does not return.
#[no_mangle]
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    unsafe { execve_result(path, argv, envp) }
}

/// Replace the current image through Linux `execveat` and `AT_EMPTY_PATH`.
///
/// The descriptor, argv, and envp remain caller-owned Linux syscall inputs.
/// A successful call does not return; Linux 5.10 `ENOSYS` is returned directly
/// rather than triggering musl's older procfs fallback.
#[no_mangle]
pub unsafe extern "C" fn fexecve(
    fd: c_int,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    // SAFETY: this is Linux/x86-64 execveat's five exact raw words; the C
    // caller owns descriptor and pointer validity for image replacement.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_EXECVEAT,
            i64::from(fd),
            EMPTY_PATH.as_ptr() as usize as i64,
            argv as usize as i64,
            envp as usize as i64,
            AT_EMPTY_PATH,
        )
    };
    c_status(result)
}
