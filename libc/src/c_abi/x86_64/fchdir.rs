//! Selected static Linux/x86-64 `fchdir` C ABI boundary.
//!
//! This private compatibility leaf owns exactly
//! `int fchdir(int directory_descriptor)`. It first sends the descriptor to
//! Linux `fchdir=81`; only an `EBADF` result is eligible for musl's
//! `/proc/self/fd/<decimal>` fallback. A succeeding `fcntl(F_GETFD)` proves
//! that the descriptor is live, then Linux `chdir=80` resolves that fixed
//! stack pathname. This preserves musl 1.2.6's useful O_PATH-directory
//! behavior without turning the artifact into general pathname, descriptor,
//! procfs, or current-directory machinery.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/unistd/fchdir.c` maps directly to [`fchdir`], and
//! `src/internal/procfdname.c` maps to [`procfdname`]. Musl returns its first
//! raw result unless it is `-EBADF` and the F_GETFD liveness probe succeeds;
//! it then invokes `chdir` on exactly `/proc/self/fd/<fd>`. The fixed local
//! byte buffer keeps that no-allocation fallback in this one archive member.
//!
//! The SysV AMD64 ABI passes the signed four-byte descriptor in edi and
//! returns the signed `int` result in eax. Raw Linux errors in `-4095..=-1`
//! alone publish the selected initial-TLS `errno`. Calling-process CWD is
//! process-global, so callers retain all external serialization and restore
//! obligations. This leaf selects no `chdir`, `getcwd`, `fcntl`, `open`,
//! `readlink`, mount, namespace, directory-stream, allocator, cancellation,
//! loader, CRT, or public x86 support boundary.

use core::ffi::c_int;
use core::mem::size_of;

use super::{c_status, raw_syscall};

const EBADF: i64 = 9;
const F_GETFD: i64 = 1;
const SYS_FCHDIR: i64 = 81;
const SYS_CHDIR: i64 = 80;
const PROC_FD_PREFIX: &[u8] = b"/proc/self/fd/";
const PROC_FD_NAME_SIZE: usize = 15 + 3 * size_of::<c_int>();

const _: () = {
    assert!(size_of::<c_int>() == 4);
    assert!(PROC_FD_PREFIX.len() == 14);
    assert!(PROC_FD_NAME_SIZE == 27);
};

/// Write musl's fixed `/proc/self/fd/<decimal>` path into caller-local bytes.
///
/// The F_GETFD check in [`fchdir`] has already rejected a negative descriptor,
/// so this keeps the source's unsigned-int decimal conversion in a bounded
/// 27-byte stack buffer without exposing a pathname helper.
fn procfdname(path: &mut [u8; PROC_FD_NAME_SIZE], descriptor: c_int) {
    path[..PROC_FD_PREFIX.len()].copy_from_slice(PROC_FD_PREFIX);
    let mut cursor = PROC_FD_PREFIX.len();
    let mut value = descriptor as u32;

    if value == 0 {
        path[cursor] = b'0';
        path[cursor + 1] = 0;
        return;
    }

    let digits_start = cursor;
    while value != 0 {
        cursor += 1;
        value /= 10;
    }
    path[cursor] = 0;

    value = descriptor as u32;
    while value != 0 {
        cursor -= 1;
        path[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    debug_assert!(cursor == digits_start);
}

/// Change the calling process's current directory through one descriptor.
///
/// A live O_PATH directory descriptor takes musl's explicit procfs fallback;
/// every other direct result remains a normal raw Linux status-to-errno
/// translation. The process-global CWD effect and descriptor lifetime remain
/// entirely caller-owned.
#[no_mangle]
pub extern "C" fn fchdir(directory_descriptor: c_int) -> c_int {
    // SAFETY: the public descriptor is a scalar Linux `fchdir=81` argument.
    let direct = unsafe {
        raw_syscall::syscall1(SYS_FCHDIR, i64::from(directory_descriptor))
    };
    if direct != -EBADF {
        return c_status(direct);
    }

    // SAFETY: F_GETFD is musl's scalar descriptor-liveness probe. Its result
    // is deliberately not translated: a dead descriptor retains fchdir's
    // original EBADF rather than an intermediate fcntl error.
    let descriptor_is_live = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FCNTL,
            i64::from(directory_descriptor),
            F_GETFD,
        )
    } >= 0;
    if !descriptor_is_live {
        return c_status(direct);
    }

    let mut procfd_path = [0u8; PROC_FD_NAME_SIZE];
    procfdname(&mut procfd_path, directory_descriptor);
    // SAFETY: procfdname supplies the exact NUL-terminated stack path that
    // musl passes to syscall(SYS_chdir, buf); Linux validates its resolution.
    let fallback = unsafe {
        raw_syscall::syscall1(SYS_CHDIR, procfd_path.as_ptr() as i64)
    };
    c_status(fallback)
}
