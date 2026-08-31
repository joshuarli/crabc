//! Selected static Linux/x86-64 POSIX spawn-attribute scheduler-policy C ABI.
//!
//! This private leaf owns exactly musl's historical
//! `int posix_spawnattr_setschedpolicy(posix_spawnattr_t *, int)` spelling.
//! Pinned musl returns its Linux `ENOSYS` error number directly and does not
//! read, write, validate, retain, or otherwise observe either argument. Thus a
//! null attribute pointer and arbitrary signed policy value have the same
//! selected source result; no caller record layout crosses this Rust boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Source-function mapping: musl
//! `src/process/posix_spawnattr_sched.c::posix_spawnattr_setschedpolicy` maps
//! directly to [`posix_spawnattr_setschedpolicy`] below. Its complete body is
//! `return ENOSYS;`. Linux's fixed `ENOSYS` errno-number ABI is 38; this is a
//! returned status, not an `errno` write or TLS dependency.
//!
//! The System V AMD64 ABI passes the opaque attribute pointer in `rdi`, the
//! signed policy `int` in `esi`, and returns the signed error number in `eax`.
//! This does not select `posix_spawn`, `posix_spawnp`, attribute initialization,
//! flags/process-group/signal/scheduler storage access, file actions, child
//! lifecycle, real scheduler policy behavior, libc.so, a CRT, a loader, a
//! sysroot, spawn-family completion, promotion, or public x86 support.

use core::ffi::{c_int, c_void};

/// Linux's fixed status value returned by this musl compatibility leaf.
const ENOSYS: c_int = 38;

/// Return musl's unsupported scheduler-policy status without observing inputs.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setschedpolicy(
    _attributes: *mut c_void,
    _policy: c_int,
) -> c_int {
    ENOSYS
}
