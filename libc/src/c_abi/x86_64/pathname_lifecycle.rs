//! Selected static Linux/x86-64 pathname-mutation C boundary.
//!
//! This leaf owns one coherent, bounded C pathname-lifecycle block:
//! `chdir`, `getcwd`, `mkdir`, `unlink`, `rmdir`, `remove`, `rename`,
//! `link`, `symlink`, `readlink`, `chmod`, `fchmod`, and `truncate`.
//! The owned runtime additionally exposes `chroot` over the same raw boundary.
//! It composes only the raw Linux/x86-64 syscall-register boundary and the
//! selected initial-TLS C `errno` writer. It is not general pathname parsing,
//! canonicalization, directory streams, CWD virtualization, recursive
//! deletion, xattr/ACL policy, mount or namespace management, a C allocator,
//! libc.so, CRT, loader, sysroot, allocator, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/unistd/chdir.c`, `unlink.c`, `rmdir.c`, `truncate.c`, `link.c`,
//!   `symlink.c`, and `readlink.c` map to the correspondingly named entries.
//! - `src/linux/chroot.c` supplies the owned runtime's direct process-root
//!   change, preserving Linux's independent CWD and open-descriptor state.
//! - `src/stat/chmod.c`, `fchmod.c`, and `mkdir.c` map to the mode-changing
//!   and directory-creation entries.
//! - `src/stdio/remove.c` and `rename.c` map to the selected lifecycle
//!   wrappers.
//! - `src/internal/procfdname.c` supplies the fixed stack-only `/proc/self/fd`
//!   spelling used by musl's `fchmod` O_PATH fallback.
//!
//! Linux 5.10 provides each legacy x86 syscall used by this leaf, so it uses
//! musl's direct x86 forms rather than a newer-ABI fallback. `getcwd` retains
//! musl's caller-buffer validation and unreachable-directory rejection but
//! deliberately rejects its allocator-requiring null-buffer extension with
//! `EINVAL`; no C allocator boundary is selected by this static archive.

use core::ffi::{c_char, c_int, c_long, c_uint};
use core::mem::size_of;

use super::{c_ssize_status, c_status, errno, raw_syscall};

const EBADF: i64 = 9;
const EISDIR: i64 = 21;
const EINVAL: c_int = 22;
const ENOENT: c_int = 2;
const F_GETFD: i64 = 1;

const PROC_FD_PREFIX: &[u8] = b"/proc/self/fd/";
// `src/internal/procfdname.c` is shared by the selected fchmod fallback and
// the owned filesystem-mechanism source translations. Keep the fixed stack
// capacity with its source owner rather than letting each sibling invent a
// pathname buffer contract.
pub(super) const PROC_FD_NAME_SIZE: usize = 15 + 3 * size_of::<c_int>();

const _: () = {
    assert!(size_of::<c_int>() == 4);
    assert!(size_of::<c_uint>() == 4);
    assert!(size_of::<c_long>() == 8);
    assert!(size_of::<isize>() == 8);
    assert!(PROC_FD_NAME_SIZE == 27);
    assert!(PROC_FD_PREFIX.len() == 14);
};

#[inline]
fn null_with_errno(error: c_int) -> *mut c_char {
    // SAFETY: this selected C ABI leaf owns the calling initial-TLS errno
    // slot and publishes its explicit local result.
    unsafe { errno::set_errno(error) };
    core::ptr::null_mut()
}

/// Build musl's bounded `/proc/self/fd/<decimal>` fallback pathname.
///
/// The caller supplies the exact fixed-size stack storage from
/// `src/internal/procfdname.c`. `fd` is converted as an unsigned C `int`, as
/// musl does; its caller has already rejected a negative descriptor through
/// `F_GETFD` before this helper can observe it.
pub(super) fn procfdname(path: &mut [u8; PROC_FD_NAME_SIZE], fd: c_int) {
    path[..PROC_FD_PREFIX.len()].copy_from_slice(PROC_FD_PREFIX);
    let mut cursor = PROC_FD_PREFIX.len();
    let mut value = fd as u32;

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

    value = fd as u32;
    while value != 0 {
        cursor -= 1;
        path[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    debug_assert!(cursor == digits_start);
}

/// Change the calling process's current directory through Linux `chdir(2)`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall
/// duration. The process-global CWD transition and every pathname policy
/// consequence remain caller-owned.
#[no_mangle]
pub unsafe extern "C" fn chdir(path: *const c_char) -> c_int {
    // SAFETY: the caller owns the pathname pointer contract.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_CHDIR, path as usize as i64)
    };
    c_status(result)
}

/// Change the process root directory using Linux `chroot` without changing CWD.
///
/// # Safety
/// `path` must designate a readable NUL-terminated pathname during the syscall.
/// The caller owns process-wide pathname coordination and the consequences for
/// existing CWD and open descriptors; this operation is not a confinement API.
#[cfg(feature = "x86-owned-static-runtime")]
#[no_mangle]
pub unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    c_status(unsafe { raw_syscall::syscall1(raw_syscall::SYS_CHROOT, path as usize as i64) })
}

/// Obtain the absolute current-directory spelling in caller-owned storage.
///
/// # Safety
///
/// `buffer` must designate writable `capacity` bytes for the syscall duration
/// and remain valid while its result is inspected. This static no-allocation
/// leaf deliberately rejects musl's null-buffer allocation extension.
#[no_mangle]
pub unsafe extern "C" fn getcwd(buffer: *mut c_char, capacity: usize) -> *mut c_char {
    if buffer.is_null() || capacity == 0 {
        return null_with_errno(EINVAL);
    }

    // SAFETY: the caller supplies writable caller-owned storage.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_GETCWD,
            buffer as usize as i64,
            capacity as i64,
        )
    };
    if result < 0 {
        let _ = c_status(result);
        return core::ptr::null_mut();
    }

    // SAFETY: successful getcwd writes a NUL-terminated prefix beginning at
    // the caller-provided buffer. Like musl, reject the kernel's unreachable
    // non-absolute spelling rather than returning it as a C pathname.
    if result == 0 || unsafe { *buffer } != b'/' as c_char {
        return null_with_errno(ENOENT);
    }
    buffer
}

/// Create one directory through Linux `mkdir(2)`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall
/// duration. Filesystem and process-umask policy remain caller-owned.
#[no_mangle]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: c_uint) -> c_int {
    // SAFETY: the caller owns the pathname pointer contract; Linux validates
    // the scalar mode word.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_MKDIR,
            path as usize as i64,
            i64::from(mode),
        )
    };
    c_status(result)
}

/// Remove one non-directory pathname through Linux `unlink(2)`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall
/// duration. Namespace and link-lifetime policy remain caller-owned.
#[no_mangle]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    // SAFETY: the caller owns the pathname pointer contract.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_UNLINK, path as usize as i64)
    };
    c_status(result)
}

/// Remove one empty directory through Linux `rmdir(2)`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall
/// duration. Namespace and directory-lifetime policy remain caller-owned.
#[no_mangle]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    // SAFETY: the caller owns the pathname pointer contract.
    let result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_RMDIR, path as usize as i64)
    };
    c_status(result)
}

/// Remove a pathname, retrying an `EISDIR` unlink failure as `rmdir`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall
/// duration. This matches musl's unlink-then-rmdir ordering; namespace and
/// removal policy remain caller-owned.
#[no_mangle]
pub unsafe extern "C" fn remove(path: *const c_char) -> c_int {
    // SAFETY: the caller owns the pathname pointer contract.
    let mut result = unsafe {
        raw_syscall::syscall1(raw_syscall::SYS_UNLINK, path as usize as i64)
    };
    if result == -EISDIR {
        // SAFETY: preserve musl's raw intermediate result so a successful
        // directory retry does not manufacture stale EISDIR errno.
        result = unsafe {
            raw_syscall::syscall1(raw_syscall::SYS_RMDIR, path as usize as i64)
        };
    }
    c_status(result)
}

/// Atomically rename one pathname through Linux `rename(2)`.
///
/// # Safety
///
/// `old_path` and `new_path` must point to readable NUL-terminated pathnames
/// for the syscall duration. Cross-directory and replacement policy remain
/// caller-owned.
#[no_mangle]
pub unsafe extern "C" fn rename(old_path: *const c_char, new_path: *const c_char) -> c_int {
    // SAFETY: the caller owns both pathname pointer contracts.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_RENAME,
            old_path as usize as i64,
            new_path as usize as i64,
        )
    };
    c_status(result)
}

/// Create one hard link through Linux `link(2)`.
///
/// # Safety
///
/// `existing_path` and `new_path` must point to readable NUL-terminated
/// pathnames for the syscall duration. Filesystem/link policy remains
/// caller-owned.
#[no_mangle]
pub unsafe extern "C" fn link(
    existing_path: *const c_char,
    new_path: *const c_char,
) -> c_int {
    // SAFETY: the caller owns both pathname pointer contracts.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_LINK,
            existing_path as usize as i64,
            new_path as usize as i64,
        )
    };
    c_status(result)
}

/// Create one symbolic link through Linux `symlink(2)`.
///
/// # Safety
///
/// `target` and `link_path` must point to readable NUL-terminated pathnames
/// for the syscall duration. The target spelling and namespace policy remain
/// caller-owned.
#[no_mangle]
pub unsafe extern "C" fn symlink(target: *const c_char, link_path: *const c_char) -> c_int {
    // SAFETY: the caller owns both pathname pointer contracts.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_SYMLINK,
            target as usize as i64,
            link_path as usize as i64,
        )
    };
    c_status(result)
}

/// Read one symbolic-link target into caller-owned bytes.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname. When `capacity`
/// is nonzero, `buffer` must designate writable storage for that many bytes.
/// A zero capacity accepts any buffer value and follows musl's dummy-byte,
/// zero-result behavior. The output is not NUL-terminated by this API.
#[no_mangle]
pub unsafe extern "C" fn readlink(
    path: *const c_char,
    buffer: *mut c_char,
    capacity: usize,
) -> isize {
    let mut dummy = 0u8;
    let (kernel_buffer, kernel_capacity) = if capacity == 0 {
        (&mut dummy as *mut u8 as *mut c_char, 1usize)
    } else {
        (buffer, capacity)
    };
    // SAFETY: the caller owns the pathname and nonzero output contracts; the
    // local dummy is writable for the zero-capacity musl compatibility path.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_READLINK,
            path as usize as i64,
            kernel_buffer as usize as i64,
            kernel_capacity as i64,
        )
    };
    if capacity == 0 && result > 0 {
        0
    } else {
        c_ssize_status(result)
    }
}

/// Change one pathname's mode through Linux `chmod(2)`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall
/// duration. Permission, ownership, and namespace policy remain caller-owned.
#[no_mangle]
pub unsafe extern "C" fn chmod(path: *const c_char, mode: c_uint) -> c_int {
    // SAFETY: the caller owns the pathname pointer contract; Linux validates
    // the scalar mode word.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CHMOD,
            path as usize as i64,
            i64::from(mode),
        )
    };
    c_status(result)
}

/// Change one descriptor's mode, including musl's O_PATH procfs fallback.
///
/// The fallback is intentionally constrained to a live descriptor whose
/// `F_GETFD` probe succeeds after `fchmod` reports `EBADF`; other direct
/// errors preserve their original Linux `errno` result.
#[no_mangle]
pub extern "C" fn fchmod(fd: c_int, mode: c_uint) -> c_int {
    // SAFETY: both initial fchmod words are scalar Linux values.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FCHMOD,
            i64::from(fd),
            i64::from(mode),
        )
    };
    if result != -EBADF {
        return c_status(result);
    }

    // SAFETY: F_GETFD is the selected scalar descriptor-liveness probe. Do
    // not translate this intermediate result: musl returns the original
    // fchmod EBADF if the probe itself fails.
    let descriptor_is_live = unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_FCNTL, i64::from(fd), F_GETFD)
    } >= 0;
    if !descriptor_is_live {
        return c_status(result);
    }

    let mut procfd_path = [0u8; PROC_FD_NAME_SIZE];
    procfdname(&mut procfd_path, fd);
    // SAFETY: procfdname writes a NUL-terminated fixed stack pathname, and
    // Linux validates the scalar mode word.
    let fallback = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_CHMOD,
            procfd_path.as_ptr() as i64,
            i64::from(mode),
        )
    };
    c_status(fallback)
}

/// Resize one pathname through Linux `truncate(2)`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname for the syscall
/// duration. The caller owns file, range, and storage policy.
#[no_mangle]
pub unsafe extern "C" fn truncate(path: *const c_char, length: c_long) -> c_int {
    // SAFETY: the caller owns the pathname pointer contract; x86 LP64 off_t
    // is the signed 64-bit second syscall word.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_TRUNCATE,
            path as usize as i64,
            length,
        )
    };
    c_status(result)
}
