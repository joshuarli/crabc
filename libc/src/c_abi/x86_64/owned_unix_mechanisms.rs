//! Installed Linux/x86-64 filesystem and terminal C mechanisms.
//!
//! This owned product block translates pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license in
//! `COPYRIGHT`. The exact source-to-entry mapping is:
//!
//! - `src/misc/get_current_dir_name.c`: [`get_current_dir_name`];
//! - `src/linux/mount.c`: [`mount`], [`umount`], and [`umount2`];
//! - `src/termios/tcdrain.c`: [`tcdrain`];
//! - `src/linux/vhangup.c`: [`vhangup`];
//! - `src/linux/vmsplice.c`: [`vmsplice`]; and
//! - `src/legacy/isastream.c`: [`isastream`].
//!
//! The source's `getcwd(NULL, 0)` allocation branch is expressed through the
//! existing x86 caller-buffer `pathname_lifecycle::getcwd` owner and selected
//! `strdup` allocation client: a source-sized `PATH_MAX` local buffer is
//! filled first, then duplicated only on success. That preserves musl's
//! observable `PATH_MAX`, `errno`, `PWD` validation, and allocation ownership
//! without changing the established x86 `getcwd` null-buffer boundary.
//!
//! Linux 5.10 provides every direct syscall used here. `tcdrain` alone uses musl's
//! `syscall_cp(SYS_ioctl, fd, TCSBRK, 1)` cancellation point; the remaining
//! direct wrappers intentionally do not acquire cancellation, retry, mount
//! policy, STREAMS emulation, namespace management, or descriptor ownership.
//! This is a selected C ABI compatibility block, not a general filesystem or
//! terminal policy framework, loader, CRT, or public x86 support claim.

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

use super::{
    allocator_string_duplication, c_ssize_status, c_status, environment,
    pathname_lifecycle, raw_syscall, stat_compat, vector_io,
};

const PATH_MAX: usize = 4096;
const F_GETFD: i64 = 1;
const TCSBRK: i64 = 0x5409;

const _: () = {
    assert!(core::mem::size_of::<c_int>() == 4);
    assert!(core::mem::size_of::<c_uint>() == 4);
    assert!(core::mem::size_of::<c_ulong>() == 8);
    assert!(core::mem::size_of::<usize>() == 8);
};

/// Allocate the logical current-directory spelling when `PWD` names `.`.
///
/// # Safety
///
/// This entry takes no caller pointer. A non-null result is an allocation from
/// the selected C allocator and must be released exactly once through the
/// matching C `free` entry after the caller has stopped using the returned
/// NUL-terminated string. Concurrent mutation of the process environment or
/// current directory follows C's ordinary caller synchronization obligations.
#[no_mangle]
pub unsafe extern "C" fn get_current_dir_name() -> *mut c_char {
    // SAFETY: the constant is a readable NUL-terminated C name owned by this
    // module; getenv returns a borrowed process-environment pointer.
    let pwd = unsafe { environment::getenv(b"PWD\0".as_ptr().cast()) };
    if !pwd.is_null() && unsafe { pwd.read() } != 0 {
        // Preserve source short-circuiting: a failed PWD stat must not issue a
        // second `stat(".")` request before the physical fallback.
        if let Some(pwd_identity) = unsafe { stat_compat::stat_device_and_inode(pwd) } {
            // SAFETY: this fixed NUL-terminated dot pathname is valid through
            // the complete private metadata observation.
            if let Some(dot_identity) = unsafe {
                stat_compat::stat_device_and_inode(b".\0".as_ptr().cast())
            } {
                if pwd_identity == dot_identity {
                    // SAFETY: a valid `PWD` environment value is a readable
                    // NUL-terminated source string for the selected allocator
                    // client, exactly as in musl's `strdup(res)` branch.
                    return unsafe { allocator_string_duplication::strdup(pwd) };
                }
            }
        }
    }

    // `getcwd(NULL, 0)` in the pinned source places a PATH_MAX local array on
    // its own stack before strdup. Reuse the adjacent x86 owner rather than
    // widening its separately documented null-buffer API.
    let mut current = [0 as c_char; PATH_MAX];
    // SAFETY: `current` is source-sized writable caller storage through this
    // call. The existing owner publishes kernel and unreachable-CWD errors.
    if unsafe { pathname_lifecycle::getcwd(current.as_mut_ptr(), current.len()) }.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: successful getcwd filled the local buffer with a NUL-terminated
    // physical pathname. strdup transfers it to selected allocator storage.
    unsafe { allocator_string_duplication::strdup(current.as_ptr()) }
}

/// Request a Linux mount operation with kernel-owned authority.
///
/// # Safety
///
/// Every non-null pathname pointer must name a readable NUL-terminated string
/// for the syscall duration. `data` must satisfy the requested filesystem
/// type's Linux input contract. The caller authorizes and synchronizes all
/// namespace, mount-tree, device, and path-lifetime effects.
#[no_mangle]
pub unsafe extern "C" fn mount(
    source: *const c_char,
    target: *const c_char,
    filesystem_type: *const c_char,
    flags: c_ulong,
    data: *const c_void,
) -> c_int {
    // SAFETY: the caller owns every raw Linux pathname/data-pointer and mount
    // authority requirement; syscall5 places all C words in Linux order.
    c_status(unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_MOUNT,
            source as usize as i64,
            target as usize as i64,
            filesystem_type as usize as i64,
            flags as i64,
            data as usize as i64,
        )
    })
}

/// Detach one Linux mount using musl's zero-flag `umount2` route.
///
/// # Safety
///
/// `target` must name a readable NUL-terminated pathname for the syscall
/// duration. The caller authorizes and synchronizes the resulting mount-tree
/// and namespace transition.
#[no_mangle]
pub unsafe extern "C" fn umount(target: *const c_char) -> c_int {
    // SAFETY: the caller owns the pathname and mount-transition contract.
    c_status(unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_UMOUNT2, target as usize as i64, 0)
    })
}

/// Detach one Linux mount with caller-selected `umount2(2)` flags.
///
/// # Safety
///
/// `target` must name a readable NUL-terminated pathname for the syscall
/// duration. The caller authorizes and synchronizes the requested namespace
/// and mount-tree transition, including any flag-specific behavior.
#[no_mangle]
pub unsafe extern "C" fn umount2(target: *const c_char, flags: c_int) -> c_int {
    // SAFETY: the caller owns the pathname, scalar flags, and mount authority.
    c_status(unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_UMOUNT2,
            target as usize as i64,
            i64::from(flags),
        )
    })
}

/// Wait for terminal output to drain at musl's cancellation-point boundary.
///
/// The descriptor must remain live and refer to a terminal suitable for the
/// Linux `TCSBRK` request. The caller owns descriptor lifetime, output queue
/// policy, and cleanup needed if deferred thread cancellation is delivered.
#[no_mangle]
pub extern "C" fn tcdrain(file_descriptor: c_int) -> c_int {
    // SAFETY: the descriptor and TCSBRK scalar words are passed unchanged to
    // the source-selected cancellation-point syscall. No caller memory is
    // reached by this ioctl form.
    let result = unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_IOCTL,
            i64::from(file_descriptor),
            TCSBRK,
            1,
            0,
            0,
            0,
        )
    };
    c_status(result)
}

/// Hang up the calling process's controlling terminal through Linux.
///
/// # Safety
///
/// The caller authorizes and synchronizes the controlling-terminal hangup and
/// its process/session effects. This wrapper has no pointer inputs or local
/// policy; Linux owns permission and terminal validation.
#[no_mangle]
pub unsafe extern "C" fn vhangup() -> c_int {
    // SAFETY: vhangup has no pointer arguments; the caller owns its terminal
    // authority and the raw syscall boundary owns Linux result translation.
    c_status(unsafe { raw_syscall::syscall0(raw_syscall::SYS_VHANGUP) })
}

/// Transfer bytes between caller memory and a Linux pipe with `vmsplice(2)`.
///
/// # Safety
///
/// `iov` must designate `count` readable initialized vector records for the
/// call. For a writable pipe endpoint, their source ranges must be readable;
/// transferred pages must not be modified or reused while the pipe or a
/// downstream splice consumer still references them. `SPLICE_F_GIFT` additionally
/// requires page-aligned addresses and lengths, and gifted pages must never be
/// modified or reused by the caller. For a readable pipe endpoint, every range
/// Linux may fill must be writable and exclusively accessible for the call.
/// The caller owns descriptor lifetime, endpoint direction, aggregate size,
/// and any synchronization needed to uphold these memory obligations.
#[no_mangle]
pub unsafe extern "C" fn vmsplice(
    file_descriptor: c_int,
    iov: *const vector_io::IoVec,
    count: usize,
    flags: c_uint,
) -> isize {
    // SAFETY: the caller owns the complete vector/descriptor/flags contract;
    // source musl uses a direct syscall rather than a cancellation point.
    c_ssize_status(unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_VMSPLICE,
            i64::from(file_descriptor),
            iov as usize as i64,
            count as i64,
            i64::from(flags),
        )
    })
}

/// Report whether a descriptor is a STREAMS endpoint on Linux.
///
/// Linux has no STREAMS subsystem. As musl does, this still validates the
/// descriptor through `F_GETFD`: invalid descriptors return `-1` with errno,
/// while every valid descriptor returns zero without changing errno.
#[no_mangle]
pub extern "C" fn isastream(file_descriptor: c_int) -> c_int {
    // SAFETY: both syscall words are scalar descriptor/command values. The
    // selected result adapter preserves fcntl's EBADF translation.
    if c_status(unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_FCNTL, i64::from(file_descriptor), F_GETFD)
    }) < 0 {
        -1
    } else {
        0
    }
}
