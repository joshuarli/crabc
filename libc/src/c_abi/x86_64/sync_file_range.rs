//! Selected static Linux/x86-64 GNU `sync_file_range` C ABI leaf.
//!
//! This leaf owns exactly
//! `sync_file_range(int, off_t, off_t, unsigned)`. It preserves pinned musl
//! 1.2.6's x86 `SYS_sync_file_range` branch from `src/linux/sync_file_range.c`:
//! the caller-supplied descriptor, signed 64-bit position/length words, and
//! unsigned flags word reach Linux 5.10 through `sync_file_range=277` in
//! `rdi`/`rsi`/`rdx`/`r10`. The direct x86 syscall branch returns ordinary C
//! success or publishes only raw Linux `-4095..=-1` failures through the
//! selected initial-TLS `errno` translator. Musl's 32-bit
//! `SYS_sync_file_range2` argument rearrangement and absent-syscall `ENOSYS`
//! fallback are deliberately not selected.
//!
//! The leaf does not open, seek, read, write, allocate, retry, validate flags
//! or ranges, select cancellation, infer writeback completion timing, or make
//! storage-cache/power-loss durability claims. It is not `sync`, `syncfs`,
//! `fsync`, `fdatasync`, `copy_file_range`, a descriptor or pathname family,
//! a filesystem policy, libc.so, CRT, loader, sysroot, Rust facade, promotion,
//! or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/linux/sync_file_range.c` calls `syscall(SYS_sync_file_range, fd,
//! __SYSCALL_LL_O(pos), __SYSCALL_LL_E(len), flags)` when the native direct
//! request exists. Linux/x86-64 supplies that request, so this private static
//! leaf keeps only its exact four-word branch.

use core::ffi::{c_int, c_uint};

use super::{c_status, raw_syscall};

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
    assert!(core::mem::size_of::<c_uint>() == 4);
    assert!(core::mem::size_of::<i64>() == 8);
};

/// Request bounded Linux range writeback on a caller-owned descriptor.
///
/// # Safety
///
/// The caller owns the descriptor lifetime, signed offset/length words, flag
/// vocabulary, concurrent file state, and all resulting writeback behavior.
/// This direct boundary intentionally forwards kernel validation and its raw
/// error result without adding a durability or storage policy.
#[no_mangle]
pub unsafe extern "C" fn sync_file_range(
    fd: c_int,
    offset: i64,
    nbytes: i64,
    flags: c_uint,
) -> c_int {
    // SAFETY: Linux/x86-64 `sync_file_range=277` receives the caller's
    // descriptor, signed offset/length, and unsigned flags words in
    // rdi/rsi/rdx/r10. The direct x86 branch does not select musl's 32-bit
    // argument rearrangement or an ENOSYS fallback.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_SYNC_FILE_RANGE,
            i64::from(fd),
            offset,
            nbytes,
            i64::from(flags),
        )
    };
    c_status(result)
}
