//! Selected static Linux/x86-64 C descriptor-entry boundary.
//!
//! This leaf owns one coherent pathname-to-descriptor entry block: C `open`,
//! `openat`, and `creat`. It composes the Linux syscall register boundary, C
//! `errno`, and the owned runtime's cancellation window. It is not public
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
//! The owned runtime preserves that cancellation point after mode selection;
//! standalone archive selections retain raw syscalls. On x86-64, musl's
//! `open` path uses open=2 and follows a successful `O_CLOEXEC` request with a
//! private F_SETFD/FD_CLOEXEC syscall; retain that ignored-result fix-up
//! without expanding the separately selected bounded C `fcntl` status-control
//! surface. `openat` uses openat=257;
//! its four Linux arguments occupy rdi/rsi/rdx/r10 rather than C's fourth
//! argument register rcx.

use core::ffi::{c_char, c_int, c_uint, VaList};

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
unsafe fn selected_mode(flags: c_int, arguments: &mut VaList<'_>) -> i64 {
    if flags & O_CREAT != 0 || (flags & O_TMPFILE) == O_TMPFILE {
        // SAFETY: mode-requiring flags obligate the variadic caller to supply
        // one mode_t word. No variadic word is read for other flag sets.
        i64::from(unsafe { arguments.next_arg::<c_uint>() })
    } else {
        0
    }
}

// Musl's `src/fcntl/open.c` object.
static_archive_member! { open_source {
    /// Open a pathname through Linux `open(2)`.
    ///
    /// Its variadic mode is consumed only with `O_CREAT` or the complete
    /// `O_TMPFILE` mask; every other flag combination uses zero without reading
    /// a variadic argument.
    ///
    /// # Safety
    ///
    /// `path` must point to a readable NUL-terminated pathname for the duration of
    /// the syscall, unless the caller deliberately invokes Linux's `EFAULT` path.
    /// The caller owns pathname lifetime, resolution races, descriptor lifetime,
    /// and the meaning of all raw Linux open flags. The owned runtime supplies
    /// musl's pthread cancellation point before creating a descriptor.
    /// When `O_CREAT` or the complete `O_TMPFILE` mask is present, the caller
    /// must supply a mode_t-compatible variadic integer argument.
    #[no_mangle]
    #[inline(never)]
    pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mut arguments: ...) -> c_int {
        // SAFETY: the caller supplies a mode_t word exactly when the flags
        // require one; mode selection reads nothing on a two-argument call.
        let mode = unsafe { selected_mode(flags, &mut arguments) };
        // SAFETY: the caller owns the raw pathname contract. Linux x86-64 takes
        // the old open syscall's pathname/flags/mode words in rdi/rsi/rdx.
        let result = unsafe {
            #[cfg(crabc_x86_owned_runtime)]
            {
                crate::x86_64_static_c_abi::pthread_cancel::syscall_cp(
                    raw_syscall::SYS_OPEN,
                    path as usize as i64,
                    i64::from(flags | O_LARGEFILE),
                    mode,
                    0,
                    0,
                    0,
                )
            }
            #[cfg(not(crabc_x86_owned_runtime))]
            {
                raw_syscall::syscall3(
                    raw_syscall::SYS_OPEN,
                    path as usize as i64,
                    i64::from(flags | O_LARGEFILE),
                    mode,
                )
            }
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
}}

// Musl's `src/fcntl/openat.c` object.
static_archive_member! { openat_source {
    /// Open a pathname relative to one directory descriptor through Linux
    /// `openat(2)`.
    ///
    /// Its variadic mode is consumed only with `O_CREAT` or the complete
    /// `O_TMPFILE` mask; other flag combinations use zero without reading an
    /// argument. `syscall4` supplies the selected mode in Linux's r10 register.
    ///
    /// # Safety
    ///
    /// `path` must point to a readable NUL-terminated pathname for the duration of
    /// the syscall, unless deliberately testing Linux's `EFAULT` path. The caller
    /// owns `directory_descriptor` lifetime, pathname resolution races, descriptor
    /// lifetime, and all raw Linux flag semantics. The owned runtime supplies
    /// musl's pthread cancellation point.
    /// When `O_CREAT` or the complete `O_TMPFILE` mask is present, the caller
    /// must supply a mode_t-compatible variadic integer argument.
    #[no_mangle]
    pub unsafe extern "C" fn openat(
        directory_descriptor: c_int,
        path: *const c_char,
        flags: c_int,
        mut arguments: ...,
    ) -> c_int {
        // SAFETY: the caller supplies a mode_t word exactly when the flags
        // require one; mode selection reads nothing on a three-argument call.
        let mode = unsafe { selected_mode(flags, &mut arguments) };
        // SAFETY: the caller owns the raw pathname/directory-descriptor contract;
        // syscall4 routes the final Linux mode word through r10.
        let result = unsafe {
            #[cfg(crabc_x86_owned_runtime)]
            {
                crate::x86_64_static_c_abi::pthread_cancel::syscall_cp(
                    raw_syscall::SYS_OPENAT,
                    i64::from(directory_descriptor),
                    path as usize as i64,
                    i64::from(flags | O_LARGEFILE),
                    mode,
                    0,
                    0,
                )
            }
            #[cfg(not(crabc_x86_owned_runtime))]
            {
                raw_syscall::syscall4(
                    raw_syscall::SYS_OPENAT,
                    i64::from(directory_descriptor),
                    path as usize as i64,
                    i64::from(flags | O_LARGEFILE),
                    mode,
                )
            }
        };
        c_status(result)
    }
}}

// Musl's `src/fcntl/creat.c` object.
static_archive_member! { creat_source {
    /// Create or truncate one pathname through the musl `creat` flag spelling.
    ///
    /// # Safety
    ///
    /// `path` must point to a readable NUL-terminated pathname for the duration of
    /// the syscall, unless deliberately testing Linux's `EFAULT` path. The caller
    /// owns pathname lifetime, resolution races, descriptor lifetime, and umask
    /// policy. The owned runtime supplies musl's pthread cancellation point.
    #[no_mangle]
    pub unsafe extern "C" fn creat(path: *const c_char, mode: c_uint) -> c_int {
        // SAFETY: this is the pinned musl `creat` mapping to `open` with a mode-
        // requiring flag set; the caller supplies the same pathname contract.
        unsafe { open(path, O_CREAT | O_WRONLY | O_TRUNC, mode) }
    }
}}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn selected_mode_and_next(flags: c_int, mut arguments: ...) -> u64 {
        // SAFETY: fixtures always supply two c_uint words. Mode selection
        // consumes at most the first; the second cursor read is always valid.
        let mode = unsafe { selected_mode(flags, &mut arguments) } as u64;
        let next = unsafe { arguments.next_arg::<c_uint>() };
        (mode << 32) | u64::from(next)
    }

    #[test]
    fn mode_selection_consumes_only_the_creation_argument() {
        for (flags, consumes_mode) in [
            (0, false),
            (O_CLOEXEC, false),
            (0x1_0000, false), // O_DIRECTORY alone does not create a file.
            (0x40_0000, false), // The unnamed-file bit needs O_DIRECTORY too.
            (O_CREAT, true),
            (O_TMPFILE, true),
            (O_TMPFILE | O_CLOEXEC, true),
        ] {
            let mode = 0o640_u32;
            let following = 0x89ab_cdef_u32;
            let observed = unsafe { selected_mode_and_next(flags, mode, following) };
            let expected_mode = if consumes_mode { mode } else { 0 };
            let expected_next = if consumes_mode { following } else { mode };
            assert_eq!(observed, (u64::from(expected_mode) << 32) | u64::from(expected_next),
                "flags {flags:#x} must preserve the variadic cursor contract");
        }
    }

    #[test]
    fn variadic_entries_accept_calls_without_a_mode() {
        let open_entry: unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int = open;
        let openat_entry: unsafe extern "C" fn(c_int, *const c_char, c_int, ...) -> c_int = openat;
        // SAFETY: the static path is NUL-terminated and O_RDONLY requires no
        // variadic mode. Each successful descriptor is closed exactly once.
        for descriptor in unsafe {
            [open_entry(c"/dev/null".as_ptr(), 0),
                openat_entry(-100, c"/dev/null".as_ptr(), 0)]
        } {
            assert!(descriptor >= 0);
            assert_eq!(unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, i64::from(descriptor)) }, 0);
        }
    }
}
