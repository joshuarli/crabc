//! Installed owned Linux/x86-64 filesystem C mechanisms.
//!
//! This feature-gated block owns exactly `fchmodat`, `lchmod`, `fchown`,
//! `fchownat`, `mknod`, `mknodat`, `renameat`, `symlinkat`, `statx`,
//! `fallocate`, `lockf`, `preadv2`, and `pwritev2`. It composes the existing
//! raw Linux register boundary, selected initial-TLS `errno`, private x86
//! `struct stat` owner, procfd spelling, vector-I/O ABI, and owned-runtime
//! cancellation window. It adds no Rust facade, pathname normalization,
//! filesystem authority policy, general `fcntl` surface, allocation, loader,
//! CRT, sysroot, family-completion, or public x86 support claim.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/stat/fchmodat.c` and `src/stat/lchmod.c` map to [`fchmodat`] and
//!   [`lchmod`], including the Linux-5.10 `fchmodat2` `ENOSYS` fallback;
//! - `src/unistd/fchown.c` and `src/unistd/fchownat.c` map to [`fchown`] and
//!   [`fchownat`], including the live-`O_PATH` procfd retry;
//! - `src/stat/mknod.c`, `src/stat/mknodat.c`, `src/unistd/renameat.c`, and
//!   `src/unistd/symlinkat.c` map to their same-named entries;
//! - `src/linux/statx.c` maps to [`statx`] as a direct syscall. Musl's
//!   old-kernel `ENOSYS` to `fstatat` fallback is intentionally omitted because
//!   the Linux 5.10 baseline guarantees `statx`;
//! - `src/linux/fallocate.c` maps to [`fallocate`];
//! - `src/misc/lockf.c` maps to [`lockf`] and its selected `fcntl` requests;
//! - `src/linux/preadv2.c` and `src/linux/pwritev2.c` map to [`preadv2`] and
//!   [`pwritev2`], preserving their zero-flag/current-offset routing.
//!
//! Linux 5.10 has every direct request except the newer `fchmodat2=452` form.
//! The latter's `ENOSYS` is therefore a normal source-selected transition,
//! not a process-wide availability cache or a pre-5.10 compatibility claim.

use core::ffi::{c_char, c_int, c_long, c_short, c_uint, c_ulong};
use core::mem::{align_of, offset_of, size_of};

use super::{
    c_ssize_status, c_status, errno, pathname_lifecycle, raw_syscall,
    stat_compat, vector_io,
};

const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const EBADF: i64 = 9;
const EACCES: c_int = 13;
const EINVAL: c_int = 22;
const ELOOP: i64 = 40;
const ENOSYS: i64 = 38;
const EOPNOTSUPP: c_int = 95;
const F_GETFD: i64 = 1;
const F_GETLK: i64 = 5;
const F_SETLK: i64 = 6;
const F_SETLKW: i64 = 7;
const F_RDLCK: c_short = 0;
const F_WRLCK: c_short = 1;
const F_UNLCK: c_short = 2;
const F_ULOCK: c_int = 0;
const F_LOCK: c_int = 1;
const F_TLOCK: c_int = 2;
const F_TEST: c_int = 3;
const O_NOCTTY: i64 = 0x100;
const O_NOFOLLOW: i64 = 0x2_0000;
const O_CLOEXEC: i64 = 0x8_0000;
const O_PATH: i64 = 0x20_0000;
const SEEK_CUR: c_short = 1;
const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;

const _: () = {
    assert!(size_of::<c_int>() == 4);
    assert!(size_of::<c_uint>() == 4);
    assert!(size_of::<c_long>() == 8);
    assert!(size_of::<c_ulong>() == 8);
    assert!(size_of::<isize>() == 8);
};

/// Linux/x86-64's public `struct flock` representation used by [`lockf`].
///
/// The public header owns this C spelling. Keeping the private record here
/// lets the source's stack object reach only its three selected `fcntl`
/// commands without expanding the public variadic interface.
#[repr(C)]
struct Flock {
    lock_type: c_short,
    whence: c_short,
    start: c_long,
    length: c_long,
    process_id: c_int,
}

const _: () = {
    assert!(size_of::<Flock>() == 32);
    assert!(align_of::<Flock>() == 8);
    assert!(offset_of!(Flock, lock_type) == 0);
    assert!(offset_of!(Flock, whence) == 2);
    assert!(offset_of!(Flock, start) == 8);
    assert!(offset_of!(Flock, length) == 16);
    assert!(offset_of!(Flock, process_id) == 24);
};

/// Linux's installed public `struct statx_timestamp` wire record.
#[repr(C)]
struct StatxTimestamp {
    seconds: i64,
    nanoseconds: u32,
    padding: u32,
}

/// Linux's installed public 256-byte `struct statx` wire record.
///
/// Linux 5.10 writes the original defined prefix and reserves the rest. The
/// installed headers expose later definitions inside that reserved tail, so
/// retain their exact current offsets for the public ABI passed directly to
/// the kernel.
#[repr(C)]
struct Statx {
    mask: u32,
    block_size: u32,
    attributes: u64,
    link_count: u32,
    user_id: u32,
    group_id: u32,
    mode: u16,
    padding0: u16,
    inode: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    access_time: StatxTimestamp,
    birth_time: StatxTimestamp,
    change_time: StatxTimestamp,
    modification_time: StatxTimestamp,
    rdevice_major: u32,
    rdevice_minor: u32,
    device_major: u32,
    device_minor: u32,
    mount_id: u64,
    dio_memory_alignment: u32,
    dio_offset_alignment: u32,
    subvolume: u64,
    atomic_write_unit_minimum: u32,
    atomic_write_unit_maximum: u32,
    atomic_write_segment_maximum: u32,
    padding1: u32,
    padding2: [u64; 9],
}

const _: () = {
    assert!(size_of::<StatxTimestamp>() == 16);
    assert!(align_of::<StatxTimestamp>() == 8);
    assert!(offset_of!(StatxTimestamp, seconds) == 0);
    assert!(offset_of!(StatxTimestamp, nanoseconds) == 8);
    assert!(size_of::<Statx>() == 256);
    assert!(align_of::<Statx>() == 8);
    assert!(offset_of!(Statx, mask) == 0);
    assert!(offset_of!(Statx, block_size) == 4);
    assert!(offset_of!(Statx, attributes) == 8);
    assert!(offset_of!(Statx, link_count) == 16);
    assert!(offset_of!(Statx, user_id) == 20);
    assert!(offset_of!(Statx, group_id) == 24);
    assert!(offset_of!(Statx, mode) == 28);
    assert!(offset_of!(Statx, inode) == 32);
    assert!(offset_of!(Statx, size) == 40);
    assert!(offset_of!(Statx, blocks) == 48);
    assert!(offset_of!(Statx, attributes_mask) == 56);
    assert!(offset_of!(Statx, access_time) == 64);
    assert!(offset_of!(Statx, birth_time) == 80);
    assert!(offset_of!(Statx, change_time) == 96);
    assert!(offset_of!(Statx, modification_time) == 112);
    assert!(offset_of!(Statx, rdevice_major) == 128);
    assert!(offset_of!(Statx, rdevice_minor) == 132);
    assert!(offset_of!(Statx, device_major) == 136);
    assert!(offset_of!(Statx, device_minor) == 140);
    assert!(offset_of!(Statx, mount_id) == 144);
    assert!(offset_of!(Statx, dio_memory_alignment) == 152);
    assert!(offset_of!(Statx, dio_offset_alignment) == 156);
    assert!(offset_of!(Statx, subvolume) == 160);
    assert!(offset_of!(Statx, atomic_write_segment_maximum) == 176);
    assert!(offset_of!(Statx, padding2) == 184);
};

#[inline(always)]
fn raw_error(error: c_int) -> i64 {
    -i64::from(error)
}

#[inline(always)]
fn is_symlink(mode: u32) -> bool {
    mode & S_IFMT == S_IFLNK
}

/// Complete musl's `fchmodat2`-unavailable no-follow fallback.
///
/// The temporary O_PATH descriptor stays live through the procfd metadata
/// check and the final legacy `fchmodat` request; its close result is ignored
/// exactly as in `src/stat/fchmodat.c`.
unsafe fn fchmodat_nofollow_fallback(
    directory_descriptor: c_int,
    path: *const c_char,
    mode: c_uint,
) -> i64 {
    // SAFETY: the caller owns the raw pathname and directory-descriptor
    // contract. The private helper owns its complete x86 output record.
    let mode = match unsafe {
        stat_compat::fstatat_mode(directory_descriptor, path, AT_SYMLINK_NOFOLLOW)
    } {
        Ok(mode) => mode,
        Err(error) => return raw_error(error),
    };
    if is_symlink(mode) {
        return raw_error(EOPNOTSUPP);
    }

    // SAFETY: the caller owns the pathname/dirfd contract. These exact source
    // flags request an O_PATH no-follow descriptor for the fallback only.
    let opened = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_OPENAT,
            i64::from(directory_descriptor),
            path as usize as i64,
            O_PATH | O_NOFOLLOW | O_NOCTTY | O_CLOEXEC,
            0,
        )
    };
    if opened < 0 {
        return if opened == -ELOOP {
            raw_error(EOPNOTSUPP)
        } else {
            opened
        };
    }

    let descriptor = opened as c_int;
    let mut procfd_path = [0u8; pathname_lifecycle::PROC_FD_NAME_SIZE];
    pathname_lifecycle::procfdname(&mut procfd_path, descriptor);
    // SAFETY: `procfdname` produced a fixed NUL-terminated local pathname;
    // the metadata helper owns its private x86 output record.
    let result = match unsafe {
        stat_compat::fstatat_mode(AT_FDCWD, procfd_path.as_ptr().cast(), 0)
    } {
        Err(error) => raw_error(error),
        Ok(mode) if is_symlink(mode) => raw_error(EOPNOTSUPP),
        Ok(_) => {
            // SAFETY: the local procfd pathname remains valid through the raw
            // request and the scalar mode follows the C ABI's `mode_t` width.
            unsafe {
                raw_syscall::syscall3(
                    raw_syscall::SYS_FCHMODAT,
                    i64::from(AT_FDCWD),
                    procfd_path.as_ptr() as i64,
                    i64::from(mode),
                )
            }
        }
    };
    // SAFETY: `descriptor` was returned by this function's successful openat
    // request. Musl deliberately ignores close's raw result here.
    let _ = unsafe { raw_syscall::syscall1(raw_syscall::SYS_CLOSE, i64::from(descriptor)) };
    result
}

/// Change one pathname's mode relative to a caller-selected directory.
///
/// A zero flag uses legacy `fchmodat`. A nonzero flag first tries Linux's
/// newer `fchmodat2`; only its `ENOSYS` result enters the pinned-musl
/// `AT_SYMLINK_NOFOLLOW` fallback. Other flag words and all other raw errors
/// remain visible exactly where the source returns them.
///
/// # Safety
///
/// `path` must remain a readable NUL-terminated pathname for the request.
/// The caller owns directory-descriptor lifetime, namespace/permission races,
/// mode policy, and the target's resulting state.
#[no_mangle]
pub unsafe extern "C" fn fchmodat(
    directory_descriptor: c_int,
    path: *const c_char,
    mode: c_uint,
    flags: c_int,
) -> c_int {
    if flags == 0 {
        // SAFETY: the caller owns the raw dirfd/path/mode contract.
        return c_status(unsafe {
            raw_syscall::syscall3(
                raw_syscall::SYS_FCHMODAT,
                i64::from(directory_descriptor),
                path as usize as i64,
                i64::from(mode),
            )
        });
    }

    // SAFETY: fchmodat2 takes the source's four words in rdi/rsi/rdx/r10.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FCHMODAT2,
            i64::from(directory_descriptor),
            path as usize as i64,
            i64::from(mode),
            i64::from(flags),
        )
    };
    if result != -ENOSYS {
        return c_status(result);
    }
    if flags != AT_SYMLINK_NOFOLLOW {
        return c_status(raw_error(EINVAL));
    }

    // SAFETY: the caller's pathname and descriptor obligations remain live
    // through the source-faithful temporary-descriptor fallback.
    c_status(unsafe { fchmodat_nofollow_fallback(directory_descriptor, path, mode) })
}

/// Change a non-symlink pathname's mode through [`fchmodat`]'s no-follow
/// source path.
///
/// # Safety
///
/// `path` must remain a readable NUL-terminated pathname for the call. The
/// caller owns pathname resolution, permissions, and the resulting mode.
#[no_mangle]
pub unsafe extern "C" fn lchmod(path: *const c_char, mode: c_uint) -> c_int {
    // SAFETY: exact musl composition; fchmodat documents the inherited path
    // and mode obligations.
    unsafe { fchmodat(AT_FDCWD, path, mode, AT_SYMLINK_NOFOLLOW) }
}

/// Change one open descriptor's ownership, retrying a live O_PATH descriptor
/// through musl's fixed procfd pathname.
///
/// # Safety
///
/// The caller owns descriptor lifetime, authorization, uid/gid values, and
/// resulting filesystem state. An invalid descriptor intentionally requests
/// Linux's raw error behavior.
#[no_mangle]
pub unsafe extern "C" fn fchown(
    descriptor: c_int,
    user: c_uint,
    group: c_uint,
) -> c_int {
    // SAFETY: the caller owns the scalar descriptor/uid/gid request.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FCHOWN,
            i64::from(descriptor),
            i64::from(user),
            i64::from(group),
        )
    };
    if result != -EBADF {
        return c_status(result);
    }

    // SAFETY: F_GETFD is musl's narrow liveness test. Keep its result private:
    // a failed probe returns the original fchown EBADF, not its own error.
    let live = unsafe {
        raw_syscall::syscall2(raw_syscall::SYS_FCNTL, i64::from(descriptor), F_GETFD)
    } >= 0;
    if !live {
        return c_status(result);
    }

    let mut procfd_path = [0u8; pathname_lifecycle::PROC_FD_NAME_SIZE];
    pathname_lifecycle::procfdname(&mut procfd_path, descriptor);
    // SAFETY: the fixed local procfd pathname remains valid through chown.
    c_status(unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_CHOWN,
            procfd_path.as_ptr() as i64,
            i64::from(user),
            i64::from(group),
        )
    })
}

/// Change one pathname entry's ownership relative to a caller-selected
/// directory descriptor.
///
/// # Safety
///
/// `path` must remain a readable NUL-terminated pathname for the call. The
/// caller owns directory-descriptor lifetime, raw flag meaning, permissions,
/// uid/gid values, and namespace races.
#[no_mangle]
pub unsafe extern "C" fn fchownat(
    directory_descriptor: c_int,
    path: *const c_char,
    user: c_uint,
    group: c_uint,
    flags: c_int,
) -> c_int {
    // SAFETY: Linux validates the caller-owned dirfd/path/uid/gid/flag words.
    c_status(unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_FCHOWNAT,
            i64::from(directory_descriptor),
            path as usize as i64,
            i64::from(user),
            i64::from(group),
            i64::from(flags),
        )
    })
}

/// Create one special filesystem node through the direct x86 `mknod` request.
///
/// # Safety
///
/// `path` must remain a readable NUL-terminated pathname. The caller owns
/// node type/device interpretation, umask, permissions, and namespace races.
#[no_mangle]
pub unsafe extern "C" fn mknod(
    path: *const c_char,
    mode: c_uint,
    device: c_ulong,
) -> c_int {
    // SAFETY: the caller owns the raw pathname/mode/dev_t request.
    c_status(unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_MKNOD,
            path as usize as i64,
            i64::from(mode),
            device as i64,
        )
    })
}

/// Create one special filesystem node relative to a caller-selected directory.
///
/// # Safety
///
/// `path` must remain a readable NUL-terminated pathname. The caller owns
/// directory-descriptor lifetime, mode/device interpretation, umask,
/// permissions, and namespace races.
#[no_mangle]
pub unsafe extern "C" fn mknodat(
    directory_descriptor: c_int,
    path: *const c_char,
    mode: c_uint,
    device: c_ulong,
) -> c_int {
    // SAFETY: syscall4 places the dev_t machine word in x86 Linux r10.
    c_status(unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_MKNODAT,
            i64::from(directory_descriptor),
            path as usize as i64,
            i64::from(mode),
            device as i64,
        )
    })
}

/// Rename one entry between caller-selected directory descriptors.
///
/// # Safety
///
/// Both path pointers must remain readable NUL-terminated pathnames for the
/// call. The caller owns descriptor lifetimes, namespace races, and replacement
/// policy.
#[no_mangle]
pub unsafe extern "C" fn renameat(
    old_directory_descriptor: c_int,
    old_path: *const c_char,
    new_directory_descriptor: c_int,
    new_path: *const c_char,
) -> c_int {
    // SAFETY: the caller owns both raw directory/path pairs.
    c_status(unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_RENAMEAT,
            i64::from(old_directory_descriptor),
            old_path as usize as i64,
            i64::from(new_directory_descriptor),
            new_path as usize as i64,
        )
    })
}

/// Create one symbolic link relative to a caller-selected directory descriptor.
///
/// # Safety
///
/// Both path pointers must remain readable NUL-terminated strings for the
/// call. The caller owns target spelling, directory-descriptor lifetime, and
/// the resulting namespace transition.
#[no_mangle]
pub unsafe extern "C" fn symlinkat(
    target: *const c_char,
    directory_descriptor: c_int,
    link_path: *const c_char,
) -> c_int {
    // SAFETY: the caller owns the two raw pathnames and directory descriptor.
    c_status(unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_SYMLINKAT,
            target as usize as i64,
            i64::from(directory_descriptor),
            link_path as usize as i64,
        )
    })
}

/// Fill the installed public `struct statx` record for one pathname.
///
/// Linux 5.10 guarantees this direct request, which supplies caller-selected
/// flags and request mask. Its raw result, including `ENOSYS` under a caller's
/// syscall filter, is published through the C ABI unchanged; no old-kernel
/// compatibility fallback is selected.
///
/// # Safety
///
/// `path` must remain a readable NUL-terminated pathname and `output` must
/// remain writable for one aligned 256-byte public `struct statx` record. The
/// caller owns directory-descriptor lifetime, flag/mask interpretation, and
/// all namespace races.
#[no_mangle]
pub unsafe extern "C" fn statx(
    directory_descriptor: c_int,
    path: *const c_char,
    flags: c_int,
    mask: c_uint,
    output: *mut Statx,
) -> c_int {
    // SAFETY: Linux x86-64 places flags/mask/output in rdx/r10/r8.
    c_status(unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_STATX,
            i64::from(directory_descriptor),
            path as usize as i64,
            i64::from(flags),
            i64::from(mask),
            output as usize as i64,
        )
    })
}

/// Allocate file storage over one signed range through Linux `fallocate(2)`.
///
/// # Safety
///
/// The caller owns descriptor lifetime, mode-bit meaning, signed range,
/// filesystem policy, and every resulting content or allocation effect.
#[no_mangle]
pub unsafe extern "C" fn fallocate(
    descriptor: c_int,
    mode: c_int,
    offset: c_long,
    length: c_long,
) -> c_int {
    // SAFETY: syscall4 puts the source's fd/mode/off_t/off_t words in
    // rdi/rsi/rdx/r10. Linux validates all scalar semantics.
    c_status(unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FALLOCATE,
            i64::from(descriptor),
            i64::from(mode),
            offset,
            length,
        )
    })
}

/// Apply musl's selected `lockf` operation over a current-offset write lock.
///
/// # Safety
///
/// The caller owns descriptor lifetime, shared file offset, lock range, and
/// blocking/cancellation coordination. `F_LOCK` can block and uses the owned
/// runtime's same cancellation window as musl's `F_SETLKW` `fcntl` route.
#[no_mangle]
pub unsafe extern "C" fn lockf(descriptor: c_int, operation: c_int, size: c_long) -> c_int {
    let mut record = Flock {
        lock_type: F_WRLCK,
        whence: SEEK_CUR,
        start: 0,
        length: size,
        process_id: 0,
    };
    let pointer = (&mut record as *mut Flock) as usize as i64;

    match operation {
        F_TEST => {
            record.lock_type = F_RDLCK;
            // SAFETY: the local complete x86 flock record remains writable
            // through the selected F_GETLK request.
            let result = unsafe {
                raw_syscall::syscall3(
                    raw_syscall::SYS_FCNTL,
                    i64::from(descriptor),
                    F_GETLK,
                    pointer,
                )
            };
            if result < 0 {
                return c_status(result);
            }
            // SAFETY: getpid has no pointer contract and cannot produce a
            // Linux error on the selected baseline.
            let caller_process = unsafe { raw_syscall::syscall0(raw_syscall::SYS_GETPID) } as c_int;
            if record.lock_type == F_UNLCK || record.process_id == caller_process {
                0
            } else {
                // SAFETY: this source-specific conflict result owns only the
                // calling thread's existing C errno slot.
                unsafe { errno::set_errno(EACCES) };
                -1
            }
        }
        F_ULOCK => {
            record.lock_type = F_UNLCK;
            // SAFETY: Linux reads the complete local flock record.
            c_status(unsafe {
                raw_syscall::syscall3(
                    raw_syscall::SYS_FCNTL,
                    i64::from(descriptor),
                    F_SETLK,
                    pointer,
                )
            })
        }
        F_TLOCK => {
            // SAFETY: Linux reads the complete local flock record.
            c_status(unsafe {
                raw_syscall::syscall3(
                    raw_syscall::SYS_FCNTL,
                    i64::from(descriptor),
                    F_SETLK,
                    pointer,
                )
            })
        }
        F_LOCK => {
            // SAFETY: Linux reads the complete local flock record while it
            // waits. The owned cancellation owner retains the caller's
            // blocking pointer lifetime contract.
            c_status(unsafe {
                super::pthread_cancel::syscall_cp(
                    raw_syscall::SYS_FCNTL,
                    i64::from(descriptor),
                    F_SETLKW,
                    pointer,
                    0,
                    0,
                    0,
                )
            })
        }
        _ => {
            // SAFETY: musl's default switch case owns this one local errno
            // result and must not issue a fcntl request.
            unsafe { errno::set_errno(EINVAL) };
            -1
        }
    }
}

/// Read vectors with musl's `preadv2` zero-flag/current-offset routing.
///
/// # Safety
///
/// `iov` and each kernel-accessed vector must remain valid and writable for
/// the operation. The caller owns descriptor lifetime, vector count and
/// aggregate bounds, file-offset synchronization, and flag interpretation.
#[no_mangle]
pub unsafe extern "C" fn preadv2(
    descriptor: c_int,
    iov: *const vector_io::IoVec,
    count: c_int,
    offset: c_long,
    flags: c_int,
) -> isize {
    if flags == 0 {
        if offset == -1 {
            // SAFETY: inherited vector-I/O caller obligations are unchanged.
            return unsafe { vector_io::readv(descriptor, iov, count) };
        }
        // SAFETY: musl's cancellation-point request receives the signed
        // offset in low/high x86 Linux words.
        return c_ssize_status(unsafe {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_PREADV,
                i64::from(descriptor),
                iov as usize as i64,
                i64::from(count),
                offset,
                offset >> 32,
                0,
            )
        });
    }

    // SAFETY: the source's flags-bearing request keeps the same offset split
    // and routes through the owned runtime cancellation window.
    c_ssize_status(unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_PREADV2,
            i64::from(descriptor),
            iov as usize as i64,
            i64::from(count),
            offset,
            offset >> 32,
            i64::from(flags),
        )
    })
}

/// Write vectors with musl's `pwritev2` zero-flag/current-offset routing.
///
/// # Safety
///
/// `iov` and each kernel-accessed vector must remain valid and readable for
/// the operation. The caller owns descriptor lifetime, vector count and
/// aggregate bounds, file-offset synchronization, and flag interpretation.
#[no_mangle]
pub unsafe extern "C" fn pwritev2(
    descriptor: c_int,
    iov: *const vector_io::IoVec,
    count: c_int,
    offset: c_long,
    flags: c_int,
) -> isize {
    if flags == 0 {
        if offset == -1 {
            // SAFETY: inherited vector-I/O caller obligations are unchanged.
            return unsafe { vector_io::writev(descriptor, iov, count) };
        }
        // SAFETY: musl's cancellation-point request receives the signed
        // offset in low/high x86 Linux words.
        return c_ssize_status(unsafe {
            super::pthread_cancel::syscall_cp(
                raw_syscall::SYS_PWRITEV,
                i64::from(descriptor),
                iov as usize as i64,
                i64::from(count),
                offset,
                offset >> 32,
                0,
            )
        });
    }

    // SAFETY: the source's flags-bearing request keeps the same offset split
    // and routes through the owned runtime cancellation window.
    c_ssize_status(unsafe {
        super::pthread_cancel::syscall_cp(
            raw_syscall::SYS_PWRITEV2,
            i64::from(descriptor),
            iov as usize as i64,
            i64::from(count),
            offset,
            offset >> 32,
            i64::from(flags),
        )
    })
}
