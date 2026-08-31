//! Selected static Linux/x86-64 `unlockpt` C ABI.
//!
//! This is an exact, zero-policy mapping of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license:
//! `src/unistd/unlockpt.c::unlockpt` creates a private zero-valued `int` and
//! issues `ioctl(fd, TIOCSPTLCK, &unlock)`. The fixed request releases the
//! devpts lock held by an already-open master descriptor. A raw Linux failure
//! reaches the shared initial-TLS errno translator and returns `-1`, while
//! success remains zero and preserves errno exactly as musl. It reuses only
//! the existing exact raw ioctl/status boundary (`raw_syscall::SYS_IOCTL` plus
//! `c_status`), never a generic ioctl helper.
//!
//! This leaf only releases the fixed lock on a caller-owned already-open PTY
//! master. It neither opens or allocates a PTY, grants one, resolves a slave
//! pathname, transfers a descriptor, establishes a session or controlling
//! terminal, changes termios state, nor chooses any terminal/process policy.
//! PTY allocation and naming, `posix_openpt`, `grantpt`, `ptsname`/
//! `ptsname_r`, openpty/forkpty/login_tty/vhangup, terminal discovery,
//! generic ioctl, dynamic runtime, CRT, loader, sysroot, family completion,
//! promotion, and public x86 support remain outside this selected-private
//! artifact.

use core::ffi::c_int;
use core::mem::{align_of, size_of};

use super::{c_status, raw_syscall};

const TIOCSPTLCK: i64 = 0x4004_5431;

const _: [(); 4] = [(); size_of::<c_int>()];
const _: [(); 4] = [(); align_of::<c_int>()];

/// Release the fixed devpts lock on a caller-owned PTY master descriptor.
///
/// # Safety
///
/// `fd` is passed directly to Linux and must remain a valid PTY master
/// descriptor for the duration of this call when the caller requires a
/// meaningful result. The wrapper supplies only a private four-byte zero lock
/// value; Linux validates descriptor type and state and owns the resulting
/// lock transition. Invalid descriptors, non-PTY descriptors, and ordinary
/// kernel failures retain Linux's errno result. This wrapper does not open,
/// name, grant, or retain a descriptor and does not establish any terminal or
/// session state.
#[no_mangle]
pub unsafe extern "C" fn unlockpt(fd: c_int) -> c_int {
    let mut unlock: c_int = 0;
    // SAFETY: The private local has the exact Linux four-byte `int` layout
    // required by the sole TIOCSPTLCK request and lives through the syscall.
    // Linux validates fd and owns all PTY lock-state effects.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TIOCSPTLCK,
            &mut unlock as *mut c_int as usize as i64,
        )
    };
    c_status(result)
}
