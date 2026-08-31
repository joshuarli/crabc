//! Selected static Linux/x86-64 POSIX spawn-attribute destruction C ABI.
//!
//! This private leaf owns exactly musl's historical
//! `int posix_spawnattr_destroy(posix_spawnattr_t *)` spelling. Pinned musl
//! makes it a successful no-op: it does not inspect, write, free, or retain
//! the caller's opaque attribute object, including a null pointer. It has no
//! mutable state, errno, TLS, allocation, syscall, process, child, signal,
//! scheduler, file-action, or spawn-execution boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Source-function mapping: musl
//! `src/process/posix_spawnattr_destroy.c::posix_spawnattr_destroy` maps
//! directly to [`posix_spawnattr_destroy`] below. Its complete body is
//! `return 0;`.
//!
//! The System V AMD64 ABI passes the opaque pointer in `rdi` and returns the
//! signed `int` result in `eax`. Modeling the pointer as `c_void` preserves
//! that boundary without importing the installed `posix_spawnattr_t` layout:
//! the selected source never dereferences it. This does not select libc.so, a
//! CRT, a loader, a sysroot, spawn-family completion, promotion, or public x86
//! support.

use core::ffi::{c_int, c_void};

/// Preserve musl's no-op spawn-attribute destruction result.
#[no_mangle]
pub extern "C" fn posix_spawnattr_destroy(_attributes: *mut c_void) -> c_int {
    0
}
