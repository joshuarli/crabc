//! Bounded static Linux/x86-64 `strsignal` C ABI boundary.
//!
//! This private selected-static leaf owns exactly the strong public
//! `strsignal` spelling. It returns one immutable process-static description
//! for Linux x86 signal numbers 1 through 64 and the shared immutable
//! `"Unknown signal"` description for zero, negative, or out-of-domain
//! numbers. The returned C pointer must not be modified or freed. No input
//! memory is dereferenced, and the lookup has no errno, TLS, lock, allocation,
//! syscall, signal-disposition, or diagnostic-output edge.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/string/strsignal.c` supplies the Linux signal-number map, exact
//!   fixed descriptions, unknown-number clamp, and static return storage.
//! - Its x86 conditional has `SIGHUP..SIGSYS == 1..31`, so `sigmap(x)` is the
//!   identity. With `_NSIG == 65`, the source preserves `RT32` through
//!   `RT64`, including the kernel-reserved 32--34 description spellings.
//!
//! Musl passes the selected string through `LCTRANS_CUR`; this archive keeps
//! the project's admitted C/POSIX/C.UTF-8 fixed descriptions and deliberately
//! selects no locale/message-catalog translation. It is not `strerror`,
//! `strerror_l`, `psignal`, perror/err/warn printing, signal delivery or
//! disposition state, process termination, libc.so, a CRT, a loader, a
//! sysroot, general diagnostics, family completion, promotion, or public x86
//! support.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_endian = "little"
)))]
compile_error!("the x86 static strsignal leaf requires little-endian Linux/x86-64");

use core::ffi::{c_char, c_int};

const MAX_SIGNAL_NUMBER: c_int = 64;

static SIGNAL_DESCRIPTIONS: [&[u8]; 65] = [
    b"Unknown signal\0",
    b"Hangup\0",
    b"Interrupt\0",
    b"Quit\0",
    b"Illegal instruction\0",
    b"Trace/breakpoint trap\0",
    b"Aborted\0",
    b"Bus error\0",
    b"Arithmetic exception\0",
    b"Killed\0",
    b"User defined signal 1\0",
    b"Segmentation fault\0",
    b"User defined signal 2\0",
    b"Broken pipe\0",
    b"Alarm clock\0",
    b"Terminated\0",
    b"Stack fault\0",
    b"Child process status\0",
    b"Continued\0",
    b"Stopped (signal)\0",
    b"Stopped\0",
    b"Stopped (tty input)\0",
    b"Stopped (tty output)\0",
    b"Urgent I/O condition\0",
    b"CPU time limit exceeded\0",
    b"File size limit exceeded\0",
    b"Virtual timer expired\0",
    b"Profiling timer expired\0",
    b"Window changed\0",
    b"I/O possible\0",
    b"Power failure\0",
    b"Bad system call\0",
    b"RT32\0",
    b"RT33\0",
    b"RT34\0",
    b"RT35\0",
    b"RT36\0",
    b"RT37\0",
    b"RT38\0",
    b"RT39\0",
    b"RT40\0",
    b"RT41\0",
    b"RT42\0",
    b"RT43\0",
    b"RT44\0",
    b"RT45\0",
    b"RT46\0",
    b"RT47\0",
    b"RT48\0",
    b"RT49\0",
    b"RT50\0",
    b"RT51\0",
    b"RT52\0",
    b"RT53\0",
    b"RT54\0",
    b"RT55\0",
    b"RT56\0",
    b"RT57\0",
    b"RT58\0",
    b"RT59\0",
    b"RT60\0",
    b"RT61\0",
    b"RT62\0",
    b"RT63\0",
    b"RT64\0",
];

/// Return musl's fixed x86 signal-description storage.
///
/// The process-static result has C's mutable pointer type for ABI
/// compatibility, but callers must not modify or free it.
#[no_mangle]
pub extern "C" fn strsignal(signum: c_int) -> *mut c_char {
    let description = if (1..=MAX_SIGNAL_NUMBER).contains(&signum) {
        SIGNAL_DESCRIPTIONS[signum as usize]
    } else {
        SIGNAL_DESCRIPTIONS[0]
    };
    description.as_ptr().cast_mut().cast::<c_char>()
}
