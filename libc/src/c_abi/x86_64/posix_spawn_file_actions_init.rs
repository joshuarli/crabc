//! Selected static Linux/x86-64 POSIX spawn file-actions initialization C ABI.
//!
//! This private leaf owns exactly musl's historical
//! `int posix_spawn_file_actions_init(posix_spawn_file_actions_t *)` spelling.
//! It writes a null `__actions` pointer at the installed musl record's
//! eight-byte offset, then returns zero. Like musl's source, it performs no
//! null validation: the input must name a valid caller-owned
//! `posix_spawn_file_actions_t`; invalid or null pointers are outside this
//! selected C-source contract. The implementation uses an unaligned raw store
//! only to prevent debug Rust from introducing a panic path; that does not
//! enlarge musl's aligned C-object precondition.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Source-function mapping: musl
//! `src/process/posix_spawn_file_actions_init.c::posix_spawn_file_actions_init`
//! maps directly to [`posix_spawn_file_actions_init`] below. Its complete body
//! is `fa->__actions = 0; return 0;`.
//!
//! The System V AMD64 ABI passes the caller-owned file-actions pointer in
//! `rdi` and returns the signed `int` result in `eax`. Musl's installed
//! `posix_spawn_file_actions_t` begins with two `int` padding words followed
//! by its pointer-sized `__actions` member at byte offset eight. The private
//! C representation below models only that written prefix rather than
//! importing the unused padding tail. This does not select `posix_spawn`,
//! `posix_spawnp`, action addition or destruction, attribute initialization
//! or mutation/query, child lifecycle, signal or scheduler policy, libc.so,
//! a CRT, a loader, a sysroot, spawn-family completion, promotion, or public
//! x86 support.

use core::ffi::{c_int, c_void};

/// The exact prefix that musl's one-field source store reaches on x86-64.
#[repr(C)]
struct PosixSpawnFileActionsPrefix {
    _pad0: [c_int; 2],
    actions: *mut c_void,
}

/// Copy musl's empty file-actions sentinel into valid caller-owned storage.
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_init(
    file_actions: *mut c_void,
) -> c_int {
    // SAFETY: This mirrors musl's direct source field assignment. The C
    // contract requires one valid caller-owned file-actions object. The
    // unaligned primitive prevents debug-only Rust panic paths; callers still
    // owe musl's ordinary aligned C object precondition.
    unsafe {
        let prefix = file_actions.cast::<PosixSpawnFileActionsPrefix>();
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*prefix).actions),
            core::ptr::null_mut(),
        );
    }
    0
}
