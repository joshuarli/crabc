//! Selected static Linux/x86-64 POSIX spawn-attribute process-group C ABI.
//!
//! This private leaf owns exactly musl's historical
//! `int posix_spawnattr_setpgroup(posix_spawnattr_t *, pid_t)` spelling. It
//! writes the supplied process-group value into the installed musl record's
//! four-byte `__pgrp` member at byte offset four, then returns zero. Like
//! musl's source, it performs no null validation: the input must name a valid
//! caller-owned `posix_spawnattr_t`; invalid or null pointers are outside this
//! selected C-source contract. The implementation uses an unaligned raw store
//! only to prevent debug Rust from introducing a panic path; that does not
//! enlarge musl's aligned C-object precondition.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Source-function mapping: musl
//! `src/process/posix_spawnattr_setpgroup.c::posix_spawnattr_setpgroup` maps
//! directly to [`posix_spawnattr_setpgroup`] below. Its complete body is
//! `attr->__pgrp = pgrp; return 0;`.
//!
//! The System V AMD64 ABI passes the caller-owned attribute pointer in `rdi`,
//! the signed `pid_t` value in `esi`, and returns the signed `int` result in
//! `eax`. Musl's installed `posix_spawnattr_t` begins with its signed
//! `__flags` member followed by the signed `__pgrp` member at byte offset four.
//! The private C representation below models only that written prefix rather
//! than importing the unused attribute tail. This does not select
//! `posix_spawn`, `posix_spawnp`, attribute initialization, flags, process-
//! group readback, signal/scheduler accessors or mutators, file actions, child
//! lifecycle, libc.so, a CRT, a loader, a sysroot, spawn-family completion,
//! promotion, or public x86 support.

use core::ffi::{c_int, c_void};

/// The exact prefix that musl's one-field source store reaches on x86-64.
#[repr(C)]
struct PosixSpawnAttrPrefix {
    _flags: c_int,
    process_group: c_int,
}

/// Copy musl's caller-supplied process-group value into valid attribute storage.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setpgroup(
    attributes: *mut c_void,
    process_group: c_int,
) -> c_int {
    // SAFETY: This mirrors musl's direct source field assignment. The C
    // contract requires one valid caller-owned attribute object. The
    // unaligned primitive prevents debug-only Rust panic paths; callers still
    // owe musl's ordinary aligned C object precondition.
    unsafe {
        let prefix = attributes.cast::<PosixSpawnAttrPrefix>();
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*prefix).process_group),
            process_group,
        );
    }
    0
}
