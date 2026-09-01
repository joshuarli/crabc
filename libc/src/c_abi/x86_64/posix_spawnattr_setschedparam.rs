//! Selected static Linux/x86-64 POSIX spawn-attribute scheduler-parameter C ABI.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license,
//! maps `src/process/posix_spawnattr_sched.c::posix_spawnattr_setschedparam`
//! directly to [`posix_spawnattr_setschedparam`]. Its complete body is
//! `return ENOSYS;`: it returns the Linux POSIX error number `ENOSYS=38`
//! directly rather than returning `-1`, setting `errno`, reading either
//! pointer, writing an attribute priority, or issuing a scheduler syscall.
//!
//! The System V AMD64 ABI passes the declared mutable `posix_spawnattr_t *`
//! and read-only `const struct sched_param *` values in `rdi` and `rsi`, then
//! returns the signed `int` result in `eax`. Musl intentionally ignores both
//! pointer values, including null, so this target-private composition does not
//! import either record layout, pointer validation, attribute initialization,
//! scheduler parameter storage, or scheduler state. The generic AArch64
//! export and behavior remain exactly unchanged.
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
compile_error!("the x86 POSIX spawn-attribute scheduler-parameter leaf requires little-endian Linux/x86-64");

const ENOSYS: c_int = 38;

/// Return musl's unsupported POSIX spawn-attribute scheduler-parameter result.
///
/// The source body does not dereference, validate, retain, or alter either
/// declared pointer, so null and arbitrary ABI-representable pointer values
/// are accepted by this fixed compatibility return.
#[no_mangle]
pub extern "C" fn posix_spawnattr_setschedparam(
    _attributes: *mut c_void,
    _parameter: *const c_void,
) -> c_int {
    ENOSYS
}
