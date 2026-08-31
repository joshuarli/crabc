//! Selected static Linux/x86-64 GNU `syncfs(2)` C ABI boundary.
//!
//! This leaf owns exactly `int syncfs(int)`. It carries one scalar descriptor
//! word unchanged to Linux/x86-64 `syncfs=306` and changes only Linux's
//! reserved raw error range into C `-1` plus the selected initial-TLS `errno`
//! slot. It supplies no descriptor lifetime, filesystem/cache policy,
//! persistence/durability assertion, cancellation point, or runtime state.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/syncfs.c` maps directly to [`syncfs`].
//!
//! Musl's selected source is one `syscall(SYS_syncfs, fd)` wrapper. It has no fallback, initialization, weak alias, or ancillary object closure to translate. Linux retains ownership of which open descriptor types it
//! accepts and of every synchronization effect; the paired artifact proves
//! only accepted regular-file requests, stale-errno success, and closed-FD
//! `EBADF`. It intentionally does not measure storage-cache or power-loss
//! durability. This private compatibility artifact is not `sync`, `fsync`,
//! `fdatasync`, `sync_file_range`, a broad descriptor/filesystem interface,
//! libc.so, CRT, loader, sysroot, allocator/runtime support, family
//! completion, promotion, or public x86 support.

use core::ffi::c_int;

use super::{c_status, raw_syscall};

/// Forward one descriptor-associated filesystem synchronization request.
///
/// The descriptor is an opaque scalar passed directly to Linux. The caller
/// owns descriptor lifetime and all filesystem/cache consequences; success
/// means only that Linux accepted the request, not that any data is durable
/// against power loss.
#[no_mangle]
pub extern "C" fn syncfs(descriptor: c_int) -> c_int {
    // SAFETY: Linux/x86-64 syscall 306 accepts one scalar descriptor in rdi;
    // the kernel validates it and `c_status` maps only its direct raw error.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_SYNCFS, i64::from(descriptor))
    };
    c_status(result)
}
