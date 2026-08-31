//! Selected static Linux/x86-64 C `isatty` descriptor observation.
//!
//! This is an exact, zero-policy mapping of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417` under musl's MIT license:
//! `src/unistd/isatty.c::isatty` issues `ioctl(fd, TIOCGWINSZ, &winsize)` and
//! returns the raw C status plus one. The private `winsize` scratch receives
//! the kernel output but is never read or exposed; therefore success becomes
//! one and preserves errno, while a raw Linux failure becomes zero after the
//! shared initial-TLS errno translation.
//!
//! This leaf only classifies an already-owned descriptor. It neither opens nor
//! names a terminal, changes terminal state, selects a terminal-path or
//! session-discovery policy, nor delegates to the separate termios-control
//! block. PTY/session policy, C terminal naming, password input, generic
//! ioctl, dynamic runtime, CRT, loader, sysroot, family completion, promotion,
//! and public x86 support remain outside this selected-private artifact.

use core::ffi::c_int;
use core::mem::{align_of, size_of, MaybeUninit};

use super::{c_status, raw_syscall};

const TIOCGWINSZ: i64 = 0x5413;

/// Private Linux/x86-64 output storage for the sole observation request.
#[repr(C)]
struct KernelWinsize {
    rows: u16,
    columns: u16,
    x_pixels: u16,
    y_pixels: u16,
}

const _: [(); 8] = [(); size_of::<KernelWinsize>()];
const _: [(); 2] = [(); align_of::<KernelWinsize>()];

/// Classify whether an already-owned descriptor is a terminal.
///
/// # Safety
///
/// `fd` is passed directly to Linux. It must remain a valid descriptor for
/// the duration of this call when the caller requires a meaningful result;
/// invalid or non-terminal descriptors instead retain Linux's ordinary errno
/// result. No caller pointer, terminal record, policy, or state mutation is
/// involved.
#[no_mangle]
pub unsafe extern "C" fn isatty(fd: c_int) -> c_int {
    let mut winsize = MaybeUninit::<KernelWinsize>::uninit();
    // SAFETY: The private scratch has the fixed Linux x86 winsize layout and
    // remains writable for the syscall. Linux validates the descriptor.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_IOCTL,
            i64::from(fd),
            TIOCGWINSZ,
            winsize.as_mut_ptr() as usize as i64,
        )
    };

    // Pinned musl's exact `syscall(...) + 1` boolean conversion: c_status
    // preserves successful zero and maps only raw Linux errors to -1/errno.
    c_status(result) + 1
}
