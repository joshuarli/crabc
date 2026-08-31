//! Selected static Linux/x86-64 `linkat` C ABI leaf.
//!
//! This leaf owns exactly `linkat(int, const char *, int, const char *, int)`.
//! It preserves pinned musl 1.2.6's direct `SYS_linkat` body from
//! `src/unistd/linkat.c`: caller-supplied old/new directory descriptors,
//! pathnames, and flags reach Linux 5.10 unchanged. It does not choose
//! `AT_FDCWD`, resolve either pathname, interpret flags, copy bytes, allocate,
//! retry, or add a fallback. It shares only the raw Linux/x86-64 register
//! boundary and selected initial-TLS `errno` translator. It is not ordinary
//! `link`, `symlink`/`symlinkat`, `readlink`/`readlinkat`, `unlink`/`unlinkat`,
//! `rename`/`renameat`, `mkdir`/`mkdirat`, another `*at` entry, a pathname
//! lifecycle family, CWD or namespace policy, directory streams, allocation,
//! cancellation, a Rust facade, libc.so, CRT, loader, sysroot, or public x86
//! support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/unistd/linkat.c` returns
//! `syscall(SYS_linkat, fd1, existing, fd2, new, flag)`. Linux 5.10 has that
//! direct x86-64 request, so the private static leaf keeps the exact bounded
//! closure without exporting a wider pathname API.

use core::ffi::{c_char, c_int};

use super::{c_status, raw_syscall};

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
};

/// Create one hard link relative to caller-supplied directory descriptors.
///
/// # Safety
///
/// `existing_path` and `new_path` must each point to readable NUL-terminated
/// pathname bytes for the syscall duration. The caller owns both directory
/// descriptor lifetimes, namespace and permission races, flag meaning, path
/// interpretation, and resulting hard-link lifetime. Passing invalid values
/// deliberately requests the kernel's raw error result.
#[no_mangle]
pub unsafe extern "C" fn linkat(
    existing_directory_descriptor: c_int,
    existing_path: *const c_char,
    new_directory_descriptor: c_int,
    new_path: *const c_char,
    flags: c_int,
) -> c_int {
    // SAFETY: Linux/x86-64 `linkat=265` receives the caller-owned old dirfd,
    // old path, new dirfd, new path, and flag words in rdi/rsi/rdx/r10/r8.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_LINKAT,
            i64::from(existing_directory_descriptor),
            existing_path as usize as i64,
            i64::from(new_directory_descriptor),
            new_path as usize as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}
