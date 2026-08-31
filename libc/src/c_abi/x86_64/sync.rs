//! Selected static Linux/x86-64 `sync` C ABI boundary.
//!
//! This private static ABI leaf is source-mapped to pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/unistd/sync.c::sync` is the complete direct `__syscall(SYS_sync)`
//! wrapper below. Its C signature is `void sync(void)`, so musl deliberately
//! discards the raw Linux result rather than publishing an error through C
//! `errno`.
//!
//! Linux 5.10 x86-64 `sync=162` has no arguments. This leaf requests only the
//! kernel's system-wide writeback completion point; it does not establish
//! writeback timing, per-file effects, storage-cache or power-loss durability.
//! It does not select `syncfs`, `sync_file_range`, `fsync`, `fdatasync`,
//! pathname or descriptor APIs, a filesystem policy, libc.so, CRT, dynamic or
//! loader TLS, sysroot, family completion, promotion, or public x86 support.

use super::raw_syscall;

/// Request the Linux system-wide filesystem writeback completion point.
///
/// The X/Open/GNU/BSD C ABI returns no status and has no errno convention:
/// any raw kernel result remains intentionally unobservable to the C caller,
/// exactly as the pinned musl wrapper does. This is not a durability promise
/// or a substitute for the descriptor-scoped `syncfs`/`fsync` APIs.
#[no_mangle]
pub extern "C" fn sync() {
    // SAFETY: Linux/x86-64 `sync=162` consumes no arguments. The void C ABI
    // deliberately ignores the raw result without touching errno or TLS.
    let _ = unsafe { raw_syscall::syscall0(raw_syscall::SYS_SYNC) };
}
