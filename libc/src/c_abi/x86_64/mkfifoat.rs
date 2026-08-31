//! Selected static Linux/x86-64 `mkfifoat` C ABI leaf.
//!
//! This leaf owns exactly `mkfifoat(int, const char *, mode_t)`. It preserves
//! musl 1.2.6's `mode | S_IFIFO` spelling from `src/stat/mkfifoat.c` and maps
//! its direct `mknodat(fd, path, mode | S_IFIFO, 0)` closure straight to the
//! Linux 5.10 syscall. The caller supplies `fd`; this leaf does not choose an
//! `AT_FDCWD` or other pathname-resolution policy. It shares only the raw
//! Linux/x86-64 register boundary and selected initial-TLS `errno` translator.
//! It is not `mkfifo`, `mknod`, `mknodat`, device-node policy, pathname
//! resolution/canonicalization, CWD or umask policy, allocation, locale,
//! terminal/environment/process state, libc.so, CRT, loader, sysroot, or
//! public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/stat/mkfifoat.c` returns `mknodat(fd, path, mode | S_IFIFO, 0)`.
//! `src/stat/mknodat.c` then issues `SYS_mknodat`; this private leaf preserves
//! that bounded Linux 5.10 closure without exporting either wider entry.

use core::ffi::{c_char, c_int, c_uint};

use super::{c_status, raw_syscall};

const S_IFIFO: c_uint = 0o010000;

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
    assert!(core::mem::size_of::<c_uint>() == 4);
};

/// Create one FIFO relative to a caller-supplied directory descriptor.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall
/// duration. `dirfd`, namespace, permission, umask, and FIFO lifetime policy
/// remain caller-owned.
#[no_mangle]
pub unsafe extern "C" fn mkfifoat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_uint,
) -> c_int {
    // SAFETY: the caller owns the descriptor and pathname contracts. Linux/x86-64
    // `mknodat=259` receives dirfd/path/mode/dev in rdi/rsi/rdx/r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_MKNODAT,
            i64::from(dirfd),
            path as usize as i64,
            i64::from(mode | S_IFIFO),
            0,
        )
    };
    c_status(result)
}
