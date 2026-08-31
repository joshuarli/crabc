//! Selected static Linux/x86-64 `mkfifo` C ABI leaf.
//!
//! This leaf owns exactly `mkfifo(const char *, mode_t)`. It preserves musl
//! 1.2.6's `mode | S_IFIFO` spelling from `src/stat/mkfifo.c`, but issues its
//! direct Linux equivalent `mknodat(AT_FDCWD, path, mode | S_IFIFO, 0)` rather
//! than exporting or composing a wider `mknod` family. It shares only the raw
//! Linux/x86-64 register boundary and selected initial-TLS `errno` translator.
//! It is not `mkfifoat`, `mknod`, `mknodat`, device-node policy, pathname
//! resolution/canonicalization, CWD or umask policy, allocation, locale,
//! terminal/environment/process state, libc.so, CRT, loader, sysroot, or
//! public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/stat/mkfifo.c` delegates `mkfifo` to `mknod(path, mode | S_IFIFO, 0)`.
//! Linux/x86-64's `mknod` implementation reaches `mknodat` with `AT_FDCWD`,
//! so this private static leaf uses that direct Linux 5.10 syscall form while
//! deliberately leaving every wider entry unexported.

use core::ffi::{c_char, c_int, c_uint};

use super::{c_status, raw_syscall};

const AT_FDCWD: i64 = -100;
const S_IFIFO: c_uint = 0o010000;

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
    assert!(core::mem::size_of::<c_uint>() == 4);
};

/// Create one named FIFO through Linux `mknodat(2)`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall
/// duration. Namespace, permission, umask, and FIFO lifetime policy remain
/// caller-owned.
#[no_mangle]
pub unsafe extern "C" fn mkfifo(path: *const c_char, mode: c_uint) -> c_int {
    // SAFETY: the caller owns the pathname pointer contract. Linux/x86-64
    // `mknodat=259` receives dirfd/path/mode/dev in rdi/rsi/rdx/r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_MKNODAT,
            AT_FDCWD,
            path as usize as i64,
            i64::from(mode | S_IFIFO),
            0,
        )
    };
    c_status(result)
}
