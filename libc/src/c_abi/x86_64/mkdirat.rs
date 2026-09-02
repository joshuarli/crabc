//! Selected static Linux/x86-64 `mkdirat` C ABI leaf.
//!
//! This leaf owns exactly `mkdirat(int, const char *, mode_t)`. It preserves
//! pinned musl 1.2.6's direct `SYS_mkdirat` implementation from
//! `src/stat/mkdirat.c`: the caller-supplied directory descriptor, pathname,
//! and mode reach Linux 5.10 unchanged through `mkdirat=258`. The leaf does
//! not choose `AT_FDCWD`, resolve or copy path bytes, alter the mode, manage a
//! umask, allocate, retry, or add a pathname, CWD, namespace, or permission
//! policy. It shares only the raw Linux/x86-64 register boundary and selected
//! initial-TLS `errno` translator. It is not `mkdir`, `mkfifo`/`mkfifoat`,
//! `mknod`/`mknodat`, `linkat`, `symlinkat`, `unlinkat`, `renameat`, a
//! directory-stream or pathname-lifecycle family, cancellation, a Rust
//! facade, libc.so, CRT, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/stat/mkdirat.c` returns `syscall(SYS_mkdirat, fd, path, mode)`.
//! Linux/x86-64 supplies that direct Linux 5.10 request, so the private static
//! leaf keeps only the exact selected branch.

use core::ffi::{c_char, c_int, c_uint};

use super::{c_status, raw_syscall};

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
    assert!(core::mem::size_of::<c_uint>() == 4);
};

/// Create one directory relative to a caller-supplied directory descriptor.
///
/// # Safety
///
/// `path` must point to readable NUL-terminated pathname bytes for the syscall
/// duration. The caller owns descriptor lifetime, pathname interpretation,
/// CWD and namespace races, mode/umask policy, authorization, and resulting
/// filesystem state. Passing invalid values deliberately requests the kernel's
/// raw error result.
#[no_mangle]
pub unsafe extern "C" fn mkdirat(
    directory_descriptor: c_int,
    path: *const c_char,
    mode: c_uint,
) -> c_int {
    // SAFETY: Linux/x86-64 `mkdirat=258` receives the caller-owned dirfd,
    // pathname pointer, and unsigned mode word in rdi/rsi/rdx. The kernel
    // applies the process umask without a selected C umask or path fallback.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MKDIRAT,
            i64::from(directory_descriptor),
            path as usize as i64,
            i64::from(mode),
        )
    };
    c_status(result)
}
