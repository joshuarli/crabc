//! Selected static Linux/x86-64 GNU `renameat2` C ABI leaf.
//!
//! This leaf owns exactly
//! `renameat2(int, const char *, int, const char *, unsigned)`. It preserves
//! Pinned musl 1.2.6's two direct syscall branches from
//! `src/linux/renameat2.c`: zero flags issue `SYS_renameat`, while nonzero
//! flags issue `SYS_renameat2`. In musl's source that distinction is:
//! `if (!flags) return syscall(SYS_renameat, oldfd, old, newfd, new);` followed
//! by `return syscall(SYS_renameat2, oldfd, old, newfd, new, flags);`.
//! Caller-supplied directory descriptors, pathnames, and flag bits therefore
//! reach Linux 5.10 unchanged. It does not choose `AT_FDCWD`, resolve either
//! pathname, interpret flag combinations, copy bytes, allocate, retry, or add
//! a fallback. It shares only the raw Linux/x86-64 register boundary and the
//! selected initial-TLS `errno` translator. It is not ordinary `rename`,
//! `renameat`, another `*at` entry, a pathname lifecycle family, CWD or
//! namespace policy, directory streams, cancellation, a Rust facade, libc.so,
//! CRT, loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/linux/renameat2.c`. Linux 5.10 has both x86-64 syscall forms, so this
//! private static leaf retains musl's zero/nonzero routing without a legacy
//! kernel-availability fallback.

use core::ffi::{c_char, c_int, c_uint};

use super::{c_status, raw_syscall};

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
    assert!(core::mem::size_of::<c_uint>() == 4);
};

/// Rename one caller-owned pathname relative to caller-supplied descriptors.
///
/// # Safety
///
/// `old_path` and `new_path` must each point to readable NUL-terminated
/// pathname bytes for the syscall duration. The caller owns both descriptor
/// lifetimes, namespace and permission races, flag meaning, path
/// interpretation, and the resulting namespace transition. Passing invalid
/// values deliberately requests the kernel's raw error result.
#[no_mangle]
pub unsafe extern "C" fn renameat2(
    old_directory_descriptor: c_int,
    old_path: *const c_char,
    new_directory_descriptor: c_int,
    new_path: *const c_char,
    flags: c_uint,
) -> c_int {
    // SAFETY: musl's zero-flag path uses Linux/x86-64 `renameat=264` with the
    // caller's old dirfd/path and new dirfd/path in rdi/rsi/rdx/r10. Nonzero
    // flags use `renameat2=316` with the same four words plus flags in r8.
    let result = unsafe {
        if flags == 0 {
            raw_syscall::syscall4(
                raw_syscall::SYS_RENAMEAT,
                i64::from(old_directory_descriptor),
                old_path as usize as i64,
                i64::from(new_directory_descriptor),
                new_path as usize as i64,
            )
        } else {
            raw_syscall::syscall5(
                raw_syscall::SYS_RENAMEAT2,
                i64::from(old_directory_descriptor),
                old_path as usize as i64,
                i64::from(new_directory_descriptor),
                new_path as usize as i64,
                i64::from(flags),
            )
        }
    };
    c_status(result)
}
