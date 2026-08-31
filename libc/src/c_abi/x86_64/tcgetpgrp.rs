//! Selected static Linux/x86-64 C `tcgetpgrp` foreground-group observation.
//!
//! This is an exact, zero-policy mapping of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license:
//! `src/unistd/tcgetpgrp.c::tcgetpgrp` issues `ioctl(fd, TIOCGPGRP, &pgrp)`.
//! The private four-byte `int` scratch receives the kernel output and becomes
//! the result only after ioctl success. A raw Linux failure instead reaches
//! the shared initial-TLS errno translator and returns `-1`, exactly as musl.
//! It reuses only the existing exact raw ioctl/status boundary
//! (`raw_syscall::SYS_IOCTL` plus `c_status`), never a generic ioctl helper.
//!
//! This leaf only reads an already-established terminal foreground group. It
//! neither creates a session, chooses or changes a process group, names or
//! opens a terminal, changes terminal state, nor delegates to the distinct
//! termios-control block. Session/process-control policy, `tcsetpgrp`,
//! `tcgetsid`, TTY discovery and naming, PTY helpers, generic ioctl, dynamic
//! runtime, CRT, loader, sysroot, family completion, promotion, and public x86
//! support remain outside this selected-private artifact.

use core::ffi::c_int;
use core::mem::{align_of, size_of, MaybeUninit};

use super::{c_status, raw_syscall};

const TIOCGPGRP: i64 = 0x540f;

const _: [(); 4] = [(); size_of::<c_int>()];
const _: [(); 4] = [(); align_of::<c_int>()];

/// Read the foreground process-group identifier of an already-owned terminal.
///
/// # Safety
///
/// `fd` is passed directly to Linux. It must remain a valid descriptor for
/// the duration of this call when the caller requires a meaningful result;
/// invalid, non-terminal, or no-controlling-terminal descriptors instead
/// retain Linux's ordinary errno result. No caller pointer, terminal record,
/// session, or process-group state mutation is involved.
#[no_mangle]
pub unsafe extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let mut pgrp = MaybeUninit::<c_int>::uninit();
    // SAFETY: The private scratch is a writable Linux pid-sized `int`; Linux
    // validates the descriptor and writes it only when the ioctl succeeds.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TIOCGPGRP,
            pgrp.as_mut_ptr() as usize as i64,
        )
    };
    if c_status(result) < 0 {
        return -1;
    }

    // SAFETY: A successful TIOCGPGRP ioctl initialized the private output.
    unsafe { pgrp.assume_init() }
}
