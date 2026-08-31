//! Selected static Linux/x86-64 POSIX spawn-attribute process-group readback C ABI.
//!
//! Pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license,
//! maps `src/process/posix_spawnattr_getpgroup.c::posix_spawnattr_getpgroup`
//! directly to [`posix_spawnattr_getpgroup`]. Its complete body assigns
//! `attr->__pgrp` to the distinct caller-owned `pid_t` output and returns zero.
//!
//! The x86-64 `<spawn.h>` record places signed four-byte `pid_t __pgrp` at
//! byte offset four. The System V AMD64 ABI passes the read-only attribute
//! pointer in `rdi`, the writable output pointer in `rsi`, and returns the
//! signed `int` result in `eax`. This private layout boundary therefore owns
//! only that one four-byte load and store; it keeps the generic AArch64 export
//! and behavior exactly unchanged.
//!
//! This private static artifact selects only valid caller-record process-group
//! readback. It has no null/alias validation, allocation, errno, TLS, syscall,
//! spawn execution, attribute initialization or mutation, file action, fork,
//! exec, child lifecycle, signal, scheduler, libc.so, CRT, loader, sysroot,
//! family-completion, promotion, or public x86 support claim.

use core::{
    ffi::{c_int, c_void},
    mem::size_of,
};

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 POSIX spawn-attribute process-group reader requires little-endian Linux/x86-64");

// `<spawn.h>` fixes `__pgrp` immediately after its leading signed `int
// __flags`. Keep the remainder of this 336-byte caller-owned record outside
// the selected leaf rather than importing an attribute-state implementation.
const POSIX_SPAWNATTR_PROCESS_GROUP_OFFSET: usize = size_of::<c_int>();
const _: [(); 4] = [(); POSIX_SPAWNATTR_PROCESS_GROUP_OFFSET];

/// Copy musl's caller-owned POSIX spawn-attribute process group to `pgroup`.
///
/// # Safety
///
/// `attributes` must designate a valid, readable, properly aligned x86-64
/// `posix_spawnattr_t` whose `__pgrp` member is initialized. `pgroup` must
/// designate distinct valid, writable, properly aligned `pid_t` storage.
/// Null, dangling, misaligned, aliased, or concurrently accessed storage is
/// outside the source C contract.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getpgroup(
    attributes: *const c_void,
    pgroup: *mut c_int,
) -> c_int {
    // SAFETY: musl dereferences both valid, distinct caller-owned objects
    // directly. Unaligned raw operations prevent debug-only Rust panic paths;
    // they do not extend musl's ordinary aligned C object preconditions.
    unsafe {
        let source = attributes
            .cast::<u8>()
            .add(POSIX_SPAWNATTR_PROCESS_GROUP_OFFSET)
            .cast::<c_int>();
        let value = core::ptr::read_unaligned(source);
        core::ptr::write_unaligned(pgroup, value);
    }
    0
}
