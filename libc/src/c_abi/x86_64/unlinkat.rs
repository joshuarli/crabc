//! Selected static Linux/x86-64 `unlinkat` C ABI leaf.
//!
//! This leaf owns exactly `unlinkat(int, const char *, int)`. It preserves
//! pinned musl 1.2.6's direct `SYS_unlinkat` implementation from
//! `src/unistd/unlinkat.c`: the caller-supplied directory descriptor,
//! pathname, and flags reach Linux 5.10 unchanged through `unlinkat=263`.
//! The leaf does not choose `AT_FDCWD`, resolve or copy path bytes, synthesize
//! flags, allocate, retry, or add a pathname, CWD, namespace, or permission
//! policy. It shares only the raw Linux/x86-64 register boundary and selected
//! initial-TLS `errno` translator. It is not `unlink`, `rmdir`, `linkat`,
//! `symlinkat`, `readlinkat`, `renameat`, `mkdirat`, a directory-stream or
//! special-node family, cancellation, a Rust facade, libc.so, CRT, loader,
//! sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/unistd/unlinkat.c` returns `syscall(SYS_unlinkat, fd, path, flag)`.
//! Linux/x86-64 supplies that direct Linux 5.10 request, so the private static
//! leaf keeps only the exact selected branch.

use core::ffi::{c_char, c_int};

use super::{c_status, raw_syscall};

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
};

/// Remove one directory entry relative to a caller-supplied directory
/// descriptor.
///
/// # Safety
///
/// `path` must point to readable NUL-terminated pathname bytes for the syscall
/// duration. The caller owns descriptor lifetime, pathname interpretation,
/// CWD and namespace races, flags, authorization, and resulting filesystem
/// state. Passing invalid values deliberately requests the kernel's raw error
/// result.
#[no_mangle]
pub unsafe extern "C" fn unlinkat(
    directory_descriptor: c_int,
    path: *const c_char,
    flags: c_int,
) -> c_int {
    // SAFETY: Linux/x86-64 `unlinkat=263` receives the caller-owned dirfd,
    // pathname pointer, and flags in rdi/rsi/rdx. The kernel owns file versus
    // AT_REMOVEDIR directory behavior without a selected pathname fallback.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_UNLINKAT,
            i64::from(directory_descriptor),
            path as usize as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}
