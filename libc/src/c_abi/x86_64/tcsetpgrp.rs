//! Selected static Linux/x86-64 C `tcsetpgrp` foreground-group assignment.
//!
//! This is an exact, zero-policy mapping of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license:
//! `src/unistd/tcsetpgrp.c::tcsetpgrp` copies the caller-supplied `pid_t` into
//! a private `int` and issues `ioctl(fd, TIOCSPGRP, &pgrp_int)`. The fixed
//! request makes the kernel assignment; success remains zero and preserves
//! errno, while a raw Linux failure reaches the shared initial-TLS errno
//! translator and returns `-1`, exactly as musl. It reuses only the existing
//! exact raw ioctl/status boundary (`raw_syscall::SYS_IOCTL` plus `c_status`),
//! never a generic ioctl helper.
//!
//! This leaf only sends a caller-selected group to an already-established
//! terminal. It neither creates a session, chooses a group, changes process
//! membership, establishes a controlling terminal, names or opens a terminal,
//! nor delegates to the distinct termios-control block. Terminal discovery,
//! `tcgetpgrp`, `tcgetsid`, termios mutation/control, PTY/session policy,
//! generic ioctl, dynamic runtime, CRT, loader, sysroot, family completion,
//! promotion, and public x86 support remain outside this selected-private
//! artifact.

use core::ffi::c_int;
use core::mem::{align_of, size_of};

use super::{c_status, raw_syscall};

const TIOCSPGRP: i64 = 0x5410;

const _: [(); 4] = [(); size_of::<c_int>()];
const _: [(); 4] = [(); align_of::<c_int>()];

/// Assign the caller-supplied foreground process group of an owned terminal.
///
/// # Safety
///
/// `fd` is passed directly to Linux and must remain a valid terminal
/// descriptor for the duration of this call when the caller requires a
/// meaningful result. `pgrp` is forwarded unchanged as the requested group;
/// Linux validates its session membership and the caller's terminal state.
/// Invalid descriptors, non-terminals, groups, or terminal state retain
/// Linux's ordinary errno result. This wrapper does not create a session,
/// select a group, or mutate process membership itself.
#[no_mangle]
pub unsafe extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    let mut pgrp_int = pgrp;
    // SAFETY: The private local has the Linux pid-sized `int` representation
    // expected by the sole TIOCSPGRP request. Linux validates fd and pgrp.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TIOCSPGRP,
            &mut pgrp_int as *mut c_int as usize as i64,
        )
    };
    c_status(result)
}
