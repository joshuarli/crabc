//! Selected static Linux/x86-64 C descriptor-entry boundary.
//!
//! This leaf owns one coherent pathname-to-descriptor entry block: C `open`,
//! `openat`, and `creat`. It composes only the raw Linux syscall register
//! boundary and the selected initial-TLS C `errno` publisher. It is not public
//! generic C `fcntl` command coverage, pathname normalization or policy, a filesystem capability,
//! vector I/O, stdio, a general C/POSIX runtime, libc.so, CRT, pthread/TLS
//! lifecycle, dynamic TLS, loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/fcntl/open.c` maps to [`open`].
//! - `src/fcntl/openat.c` maps to [`openat`].
//! - `src/fcntl/creat.c` maps to [`creat`].
//!
//! Musl extracts the variadic mode only when `O_CREAT` is set or the complete
//! `O_TMPFILE` mask is present, supplies zero otherwise, ORs `O_LARGEFILE`
//! into its raw Linux request, and routes normal calls through `__syscall_cp`.
//! This selected direct Linux-5.10 leaf retains the mode and flag algorithms,
//! but deliberately omits pthread cancellation and cleanup. On x86-64, musl's
//! `open` path uses open=2 and follows a successful `O_CLOEXEC` request with a
//! private F_SETFD/FD_CLOEXEC syscall; retain that ignored-result fix-up
//! without expanding the separately selected bounded C `fcntl` status-control
//! surface. `openat` uses openat=257;
//! its four Linux arguments occupy rdi/rsi/rdx/r10 rather than C's fourth
//! argument register rcx.

use core::ffi::{c_char, c_int, c_uint};

use super::{c_status, raw_syscall};

const O_CREAT: c_int = 0x40;
const O_CLOEXEC: c_int = 0x80_000;
const O_LARGEFILE: c_int = 0x8_000;
const O_TMPFILE: c_int = 0x41_0000;
const O_WRONLY: c_int = 0x1;
const O_TRUNC: c_int = 0x200;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;

#[inline]
fn selected_mode(flags: c_int, mode: c_uint) -> i64 {
    if flags & O_CREAT != 0 || (flags & O_TMPFILE) == O_TMPFILE {
        i64::from(mode)
    } else {
        0
    }
}

/// Open a pathname through Linux `open(2)`.
///
/// The installed C declaration is variadic. Its optional mode is semantically
/// consumed only with `O_CREAT` or `O_TMPFILE`; a two-argument C call for every
/// other flag combination therefore follows musl's zero-mode route. The fixed
/// Rust ABI spelling has the same SysV argument registers as that C entry.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the duration of
/// the syscall, unless the caller deliberately invokes Linux's `EFAULT` path.
/// The caller owns pathname lifetime, resolution races, descriptor lifetime,
/// and the meaning of all raw Linux open flags. This direct leaf does not
/// provide musl's pthread cancellation-point behavior.
#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
    // SAFETY: the caller owns the raw pathname contract. Linux x86-64 takes
    // the old open syscall's pathname/flags/mode words in rdi/rsi/rdx.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_OPEN,
            path as usize as i64,
            i64::from(flags | O_LARGEFILE),
            selected_mode(flags, mode),
        )
    };

    if result >= 0 && flags & O_CLOEXEC != 0 {
        // Musl keeps this private post-open fix-up even though Linux 5.10
        // understands O_CLOEXEC. Its result is intentionally ignored, exactly
        // as in the pinned source; it neither exports a second fcntl entry nor
        // expands the separately selected bounded status-control surface.
        let _ = unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_FCNTL,
                result,
                i64::from(F_SETFD),
                i64::from(FD_CLOEXEC),
            )
        };
    }

    c_status(result)
}

/// Open a pathname relative to one directory descriptor through Linux
/// `openat(2)`.
///
/// The installed C declaration is variadic. Its optional mode is semantically
/// consumed only with `O_CREAT` or `O_TMPFILE`; other flag combinations use a
/// zero mode. The fixed Rust ABI spelling keeps the C fourth argument in rcx,
/// and `syscall4` moves it into Linux's required r10 register.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the duration of
/// the syscall, unless deliberately testing Linux's `EFAULT` path. The caller
/// owns `directory_descriptor` lifetime, pathname resolution races, descriptor
/// lifetime, and all raw Linux flag semantics. This direct leaf has no musl
/// pthread cancellation-point behavior.
#[no_mangle]
pub unsafe extern "C" fn openat(
    directory_descriptor: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_uint,
) -> c_int {
    // SAFETY: the caller owns the raw pathname/directory-descriptor contract;
    // syscall4 routes the final Linux mode word through r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_OPENAT,
            i64::from(directory_descriptor),
            path as usize as i64,
            i64::from(flags | O_LARGEFILE),
            selected_mode(flags, mode),
        )
    };
    c_status(result)
}

/// Create or truncate one pathname through the musl `creat` flag spelling.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the duration of
/// the syscall, unless deliberately testing Linux's `EFAULT` path. The caller
/// owns pathname lifetime, resolution races, descriptor lifetime, and umask
/// policy. This direct leaf has no musl pthread cancellation-point behavior.
#[no_mangle]
pub unsafe extern "C" fn creat(path: *const c_char, mode: c_uint) -> c_int {
    // SAFETY: this is the pinned musl `creat` mapping to `open` with a mode-
    // requiring flag set; the caller supplies the same pathname contract.
    unsafe { open(path, O_CREAT | O_WRONLY | O_TRUNC, mode) }
}
