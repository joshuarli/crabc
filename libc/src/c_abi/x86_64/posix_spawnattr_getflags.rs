//! Selected static Linux/x86-64 POSIX spawn-attribute flag-readback C ABI.
//!
//! This private leaf owns exactly musl's historical
//! `int posix_spawnattr_getflags(const posix_spawnattr_t *restrict, short *restrict)`
//! spelling. It reads the first, signed `int __flags` member from a valid
//! caller-owned `posix_spawnattr_t`, stores its `short` conversion through a
//! distinct valid caller-owned output pointer, then returns zero. Like musl's
//! source, it performs no null or alias validation: invalid, null, or
//! overlapping pointers are outside this selected C-source contract. The
//! implementation uses raw unaligned load/store intrinsics only to prevent
//! debug Rust from introducing panic paths; that does not enlarge musl's C
//! valid-storage precondition or make unaligned C calls supported.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Source-function mapping: musl
//! `src/process/posix_spawnattr_getflags.c::posix_spawnattr_getflags` maps
//! directly to [`posix_spawnattr_getflags`] below. Its complete body is
//! `*flags = attr->__flags; return 0;`.
//!
//! The System V AMD64 ABI passes the attribute and output pointers in `rdi`
//! and `rsi`, then returns the signed `int` result in `eax`. Musl's installed
//! `posix_spawnattr_t` declares `int __flags` as its offset-zero first member;
//! the private C representation below models only that read prefix rather
//! than importing the rest of the caller-owned attribute layout. This does
//! not select attribute initialization or mutation, `posix_spawn`,
//! `posix_spawnp`, file actions, child lifecycle, signal or scheduler policy,
//! libc.so, a CRT, a loader, a sysroot, spawn-family completion, promotion,
//! or public x86 support.

use core::ffi::{c_int, c_short, c_void};

/// Copy musl's caller-owned spawn-attribute flags into a `short` result.
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getflags(
    attributes: *const c_void,
    flags: *mut c_short,
) -> c_int {
    // SAFETY: This mirrors musl's direct source dereferences. The C contract
    // requires valid, distinct caller-owned attribute and output storage.
    // Unaligned primitives prevent debug-only Rust panic paths; callers still
    // owe musl's ordinary aligned C object preconditions.
    unsafe {
        let value = core::ptr::read_unaligned(attributes as *const c_int);
        core::ptr::write_unaligned(flags, value as c_short);
    }
    0
}
