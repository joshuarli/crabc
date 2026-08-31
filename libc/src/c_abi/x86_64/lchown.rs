//! Selected static Linux/x86-64 `lchown` C ABI leaf.
//!
//! This leaf owns exactly `lchown(const char *, uid_t, gid_t)`. It preserves
//! pinned musl 1.2.6's x86 direct `SYS_lchown` branch from
//! `src/unistd/lchown.c`: the caller-supplied pathname, unsigned owner, and
//! unsigned group words reach Linux 5.10 unchanged through `lchown=94`.
//! Musl's non-x86 `fchownat(AT_FDCWD, ..., AT_SYMLINK_NOFOLLOW)` fallback is
//! deliberately not selected because Linux/x86-64 has the direct request. The
//! leaf does not resolve its pathname, choose a CWD, synthesize flags, copy
//! bytes, allocate, retry, or add a permission-policy layer. It shares only
//! the raw Linux/x86-64 register boundary and selected initial-TLS `errno`
//! translator. It is not `chown`, `fchown`, `fchownat`, another ownership or
//! credential entry, a pathname lifecycle family, CWD or namespace policy,
//! directory streams, allocation, cancellation, a Rust facade, libc.so, CRT,
//! loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/unistd/lchown.c` returns `syscall(SYS_lchown, path, uid, gid)` when
//! `SYS_lchown` exists. Linux/x86-64 supplies that direct Linux 5.10 request,
//! so the private static leaf keeps only the exact selected branch.

use core::ffi::{c_char, c_int, c_uint};

use super::{c_status, raw_syscall};

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
    assert!(core::mem::size_of::<c_uint>() == 4);
};

/// Change one pathname entry's ownership without following its final symlink.
///
/// # Safety
///
/// `path` must point to readable NUL-terminated pathname bytes for the syscall
/// duration. The caller owns pathname interpretation, CWD and namespace
/// races, authorization, owner/group values, and resulting filesystem state.
/// Passing invalid values deliberately requests the kernel's raw error result.
#[no_mangle]
pub unsafe extern "C" fn lchown(
    path: *const c_char,
    owner: c_uint,
    group: c_uint,
) -> c_int {
    // SAFETY: Linux/x86-64 `lchown=94` receives the caller-owned path, uid,
    // and gid words in rdi/rsi/rdx. The direct request owns final-symlink
    // no-follow semantics without a selected fchownat fallback.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LCHOWN,
            path as usize as i64,
            i64::from(owner),
            i64::from(group),
        )
    };
    c_status(result)
}
