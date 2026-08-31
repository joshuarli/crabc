//! Selected static Linux/x86-64 POSIX spawn-attribute scheduler-policy C ABI.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license,
//! maps `src/process/posix_spawnattr_sched.c::posix_spawnattr_getschedpolicy`
//! directly to [`posix_spawnattr_getschedpolicy`]. Its complete body is
//! `return ENOSYS;`: it returns the POSIX error number `ENOSYS=38` directly,
//! rather than returning `-1`, setting `errno`, reading an attribute field, or
//! issuing a scheduler syscall.
//!
//! The System V AMD64 ABI passes the declared `const posix_spawnattr_t *` and
//! `int *` values in `rdi` and `rsi`, then returns that signed `int` in `eax`.
//! Musl's body intentionally ignores both pointer values, including null, so
//! this target-private composition does not import a record layout, pointer
//! validation, attribute initialization, or scheduler state. It preserves the
//! generic AArch64 export and behavior exactly unchanged.
//!
//! This private static artifact selects only this one compatibility return. It
//! has no caller-memory access, allocation, errno, TLS, syscall, spawn
//! execution, file action, fork, exec, child lifecycle, signal delivery,
//! scheduler policy or parameter behavior, libc.so, CRT, loader, sysroot,
//! family-completion, promotion, or public x86 support claim.

use core::ffi::{c_int, c_void};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 POSIX spawn-attribute scheduler-policy leaf requires little-endian Linux/x86-64");

const ENOSYS: c_int = 38;

/// Return musl's unsupported POSIX spawn-attribute scheduler-policy result.
///
/// The source body does not dereference either declared pointer. In
/// particular, it does not validate either argument or alter `errno`.
#[no_mangle]
pub extern "C" fn posix_spawnattr_getschedpolicy(
    _attributes: *const c_void,
    _policy: *mut c_int,
) -> c_int {
    ENOSYS
}
