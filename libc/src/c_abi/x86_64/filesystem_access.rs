//! Selected static Linux/x86-64 C filesystem-access boundary.
//!
//! This leaf owns exactly `access`, `faccessat`, `euidaccess`, and musl's weak
//! same-address `eaccess` alias. It uses direct Linux permission checks with
//! the caller's pathname and directory-descriptor lifetime; it provides no
//! pathname normalization, filesystem capability, credential management,
//! `fchmodat`/`lchmod`, cancellation point, libc.so, CRT, loader, sysroot, or
//! public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/unistd/access.c` maps to [`access`] and its direct x86 `access=21`
//!   request.
//! - `src/unistd/faccessat.c` maps to [`faccessat`]: zero flags use legacy
//!   `faccessat=269`, while nonzero flags use `faccessat2=439`.
//! - `src/legacy/euidaccess.c` maps to [`euidaccess`] and its
//!   `faccessat(AT_FDCWD, path, mode, AT_EACCESS)` composition. Musl's
//!   `weak_alias(euidaccess, eaccess)` is retained as an assembler alias.
//!
//! Linux 5.10 includes `faccessat2`; this deliberately bounded target has no
//! pre-5.10 ENOSYS fallback, credential emulation, path-copy fallback, signal
//! handling, or musl `__syscall_cp` cancellation-point machinery. Linux
//! validates mode and flag bits and reports raw errors through the selected
//! initial-TLS C errno translator.

use core::ffi::{c_char, c_int};

use super::{c_status, raw_syscall};

const AT_FDCWD: c_int = -100;
const AT_EACCESS: c_int = 0x200;

// Musl weak_alias(euidaccess, eaccess) makes both ELF names identify the same
// implementation. A Rust weak forwarding wrapper would use another address
// and silently widen the source-specific alias contract.
core::arch::global_asm!(
    ".weak eaccess",
    ".set eaccess, euidaccess",
);

/// Test a pathname against Linux's real-ID permission check through
/// `access(2)`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the duration
/// of the syscall, unless the caller deliberately requests Linux's `EFAULT`
/// behavior. The caller owns pathname lifetime, resolution races, and the
/// meaning of the raw Linux access-mode bits. This direct leaf has no musl
/// pthread-cancellation behavior.
#[no_mangle]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    // SAFETY: the caller owns the raw pathname and access-mode contract; Linux
    // x86-64 takes them in rdi/rsi for the direct access=21 request.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_ACCESS,
            path as usize as i64,
            i64::from(mode),
        )
    };
    c_status(result)
}

/// Test a pathname relative to a directory descriptor through Linux
/// `faccessat(2)` or its flags-bearing `faccessat2(2)` form.
///
/// A zero `flags` word preserves musl's three-argument legacy
/// `faccessat=269` route. Any nonzero word uses Linux 5.10's
/// `faccessat2=439` request, whose fourth argument is moved from the C ABI's
/// rcx into Linux x86-64's r10 register. No availability fallback or
/// credentials-in-userspace emulation is selected.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the duration
/// of the syscall, unless the caller deliberately requests Linux's `EFAULT`
/// behavior. The caller owns `directory_descriptor` lifetime, pathname
/// resolution races, and the meaning of all raw Linux mode and flag bits.
/// This direct leaf has no musl pthread-cancellation behavior.
#[no_mangle]
pub unsafe extern "C" fn faccessat(
    directory_descriptor: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    let result = if flags == 0 {
        // SAFETY: the caller owns the raw directory-descriptor, pathname, and
        // access-mode contract. Legacy faccessat has no fourth flags argument.
        unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_FACCESSAT,
                i64::from(directory_descriptor),
                path as usize as i64,
                i64::from(mode),
            )
        }
    } else {
        // SAFETY: the caller owns the raw directory-descriptor, pathname,
        // access-mode, and flags contract. syscall4 routes flags through r10.
        unsafe {
            raw_syscall::syscall4(
                raw_syscall::SYS_FACCESSAT2,
                i64::from(directory_descriptor),
                path as usize as i64,
                i64::from(mode),
                i64::from(flags),
            )
        }
    };
    c_status(result)
}

/// Test a pathname using Linux's effective-ID permission check.
///
/// This is musl's `faccessat(AT_FDCWD, path, mode, AT_EACCESS)` composition;
/// [`eaccess`] is its weak same-address ELF alias.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the duration
/// of the syscall, unless the caller deliberately requests Linux's `EFAULT`
/// behavior. The caller owns pathname lifetime, resolution races, and the
/// raw access-mode bits. This direct leaf has no musl pthread-cancellation
/// behavior.
#[no_mangle]
pub unsafe extern "C" fn euidaccess(path: *const c_char, mode: c_int) -> c_int {
    // SAFETY: euidaccess has the same caller-owned pathname/mode obligations
    // as faccessat and fixes the remaining two arguments to musl's contract.
    unsafe { faccessat(AT_FDCWD, path, mode, AT_EACCESS) }
}
