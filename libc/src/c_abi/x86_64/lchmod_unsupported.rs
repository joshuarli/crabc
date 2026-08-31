//! Linux/x86-64 `lchmod` unsupported C-ABI boundary.
//!
//! Linux has no operation that changes a symbolic link's permission bits.
//! `lchmod` is nevertheless a GNU/BSD-visible musl C entry, so the selected
//! x86 archive provides the same useful ABI result as the AArch64 runtime:
//! `-1` with `errno == EOPNOTSUPP` (`ENOTSUP` on Linux) and no target-following
//! behavior. This intentionally does not turn into a filesystem-policy or
//! pathname-resolution layer.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Musl's `src/stat/lchmod.c` calls `fchmodat(AT_FDCWD, path, mode,
//! AT_SYMLINK_NOFOLLOW)`. Linux 5.10 has no `fchmodat2` flag-bearing syscall;
//! for the selected no-follow symlink boundary pinned musl reports the same
//! unsupported result. The x86 leaf deliberately follows the existing
//! AArch64 `filesystem_paths_exports.rs` profile by publishing that constant
//! result before pathname resolution. Thus an absent pathname need not match
//! musl's delegated `fchmodat` error; no raw syscall, fallback, allocation,
//! cancellation point, or C allocator is selected.
//!
//! This is not `fchmodat`, general permission policy, `chmod` target following,
//! libc.so, CRT, dynamic TLS, loader, sysroot, filesystem-family completion,
//! promotion, or public x86 support.

use core::ffi::{c_char, c_int, c_uint};

use super::errno;

const EOPNOTSUPP: c_int = 95;

/// Report Linux's deliberate unsupported no-follow mode-change result.
///
/// # Safety
///
/// The C ABI accepts the usual pathname pointer and `mode_t` scalar. This
/// selected Linux profile deliberately does not dereference `path`, resolve a
/// target, or inspect either argument before it writes the calling thread's
/// initial-TLS `errno` slot. Callers still own all wider C pathname-lifetime
/// and filesystem-policy expectations, which are outside this leaf.
#[no_mangle]
pub unsafe extern "C" fn lchmod(_path: *const c_char, _mode: c_uint) -> c_int {
    // SAFETY: this selected x86 C ABI owns the caller's initial-TLS errno slot
    // for this fixed Linux unsupported result.
    unsafe { errno::set_errno(EOPNOTSUPP) };
    -1
}
