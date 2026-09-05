//! Static Linux/x86-64 `sys/stat.h` compatibility boundary.
//!
//! This is one selected x86 `crabc-libc` artifact leaf. It owns only
//! the four direct metadata calls and their historical stat-version aliases:
//! `stat`, `lstat`, `fstat`, `fstatat`, `__xstat`, `__lxstat`, `__fxstat`, and
//! `__fxstatat`. It deliberately composes only the already-proved raw syscall
//! register ABI and one initial-TLS `errno` slot. It does not select a dynamic
//! `libc.so`, a general syscall wrapper, pthread/TLS lifecycle, allocator,
//! CRT, sysroot, or the rest of the C/POSIX runtime.
//!
//! The record is the Linux/x86-64 LP64 public `struct stat` in
//! `include/bits/stat.h`, not the differently ordered AArch64 record in the
//! active `c_abi` root. Linux `fstat=5` fills that exact record; `stat`,
//! `lstat`, and `fstatat` use `newfstatat=262` with the x86 fourth syscall
//! argument in `r10`, as implemented by `syscall4`.

use core::ffi::{c_char, c_int};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

/// Private x86 LP64 `struct timespec` storage used by [`Stat`].
#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}

/// Exact Linux/x86-64 public `struct stat` record.
///
/// This stays private because the selected C ABI owns the public record
/// spelling in `include/bits/stat.h`; Rust callers continue to use the typed
/// `crabc-rs` metadata facade instead of a C-compatible layout.
#[repr(C)]
pub struct Stat {
    device: u64,
    inode: u64,
    link_count: u64,
    mode: u32,
    user_id: u32,
    group_id: u32,
    padding0: u32,
    rdevice: u64,
    size: i64,
    block_size: i64,
    blocks: i64,
    access_time: Timespec,
    modification_time: Timespec,
    change_time: Timespec,
    unused: [i64; 3],
}

/// Private path metadata view for selected sibling C ABI leaves.
///
/// This retains the sole x86 `struct stat` layout owner while admitting only
/// the mode/device/inode observations needed by a bounded path operation.
/// The public C record remains owned by this module and is borrowed only for
/// the duration of a sibling callback.
#[cfg(feature = "x86-filesystem-traversal")]
pub(super) struct PathMetadata {
    record: Stat,
}

#[cfg(feature = "x86-filesystem-traversal")]
impl PathMetadata {
    #[inline]
    pub(super) fn zeroed() -> Self {
        Self {
            record: unsafe { core::mem::zeroed() },
        }
    }

    #[inline]
    pub(super) fn mode(&self) -> u32 {
        self.record.mode
    }

    #[inline]
    pub(super) fn device(&self) -> u64 {
        self.record.device
    }

    #[inline]
    pub(super) fn inode(&self) -> u64 {
        self.record.inode
    }

    #[inline]
    pub(super) fn as_stat_ptr(&self) -> *const Stat {
        &self.record
    }
}

/// Return the two metadata words consumed by musl's `ftok` formula.
///
/// This keeps the x86 `struct stat` layout in its sole owner while allowing
/// the separately selected SysV IPC leaf to reproduce `src/ipc/ftok.c`
/// without defining a second, drifting copy of that private Rust record.
/// `stat` itself owns C errno publication, so a failed lookup returns `None`
/// after preserving its normal C ABI failure result.
///
/// # Safety
///
/// `path` must meet the public `stat` pathname-pointer contract.
pub(super) unsafe fn stat_device_and_inode(path: *const c_char) -> Option<(u64, u64)> {
    // SAFETY: zero is a valid initial representation for private output
    // storage and `stat` fills the kernel-defined x86 record on success.
    let mut metadata: Stat = unsafe { core::mem::zeroed() };
    // SAFETY: the caller upholds the pathname contract and this local owns one
    // complete private x86 `struct stat` output record.
    if unsafe { stat(path, &mut metadata) } < 0 {
        None
    } else {
        Some((metadata.device, metadata.inode))
    }
}

const _: () = {
    assert!(size_of::<Timespec>() == 16);
    assert!(align_of::<Timespec>() == 8);
    assert!(size_of::<Stat>() == 144);
    assert!(align_of::<Stat>() == 8);
    assert!(offset_of!(Stat, device) == 0);
    assert!(offset_of!(Stat, inode) == 8);
    assert!(offset_of!(Stat, link_count) == 16);
    assert!(offset_of!(Stat, mode) == 24);
    assert!(offset_of!(Stat, user_id) == 28);
    assert!(offset_of!(Stat, group_id) == 32);
    assert!(offset_of!(Stat, rdevice) == 40);
    assert!(offset_of!(Stat, size) == 48);
    assert!(offset_of!(Stat, block_size) == 56);
    assert!(offset_of!(Stat, blocks) == 64);
    assert!(offset_of!(Stat, access_time) == 72);
    assert!(offset_of!(Stat, modification_time) == 88);
    assert!(offset_of!(Stat, change_time) == 104);
};

/// Issue `newfstatat` without imposing Rust pointer validity on the C ABI.
///
/// # Safety
///
/// `path` and `buffer` must satisfy Linux `newfstatat(2)`'s complete pointer,
/// lifetime, and accessibility requirements. `directory_fd` and `flags` are
/// passed directly to the kernel.
#[inline]
unsafe fn raw_newfstatat(
    directory_fd: c_int,
    path: *const c_char,
    buffer: *mut Stat,
    flags: c_int,
) -> i64 {
    // SAFETY: the caller upholds the exact raw `newfstatat` contract. The
    // x86 syscall wrapper places `flags` in r10 rather than C ABI rcx.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_NEWFSTATAT,
            i64::from(directory_fd),
            path as usize as i64,
            buffer as usize as i64,
            i64::from(flags),
        )
    };
    result
}

/// Read the `st_mode` fact consumed by the owned source-faithful `fchmodat`
/// fallback without publishing an intermediate errno.
///
/// The caller owns the final C result boundary because musl's `fchmodat` must
/// close a temporary descriptor after its later lookup. The C ABI record stays
/// private to this module; no sibling receives a broader metadata projection.
///
/// # Safety
///
/// `path` must satisfy Linux `newfstatat(2)`'s pathname, lifetime, and
/// accessibility rules for the whole raw request. `directory_fd` and `flags`
/// are forwarded unchanged.
#[cfg(feature = "x86-owned-static-runtime")]
#[inline(always)]
pub(super) unsafe fn fstatat_mode(
    directory_fd: c_int,
    path: *const c_char,
    flags: c_int,
) -> Result<u32, c_int> {
    // SAFETY: zero is a valid initial representation for the kernel-filled
    // private x86 record.
    let mut record: Stat = unsafe { core::mem::zeroed() };
    // SAFETY: the caller supplies the raw pathname contract and `record` is
    // one complete private writable Linux x86 `struct stat` output record.
    let result = unsafe {
        raw_newfstatat(directory_fd, path, &mut record as *mut Stat, flags)
    };
    if result < 0 && result >= -4_095 {
        return Err(result.wrapping_neg() as c_int);
    }

    Ok(record.mode)
}

/// Issue `newfstatat` and publish its raw result through the C ABI errno
/// boundary.
///
/// # Safety
///
/// `path` and `buffer` must satisfy Linux `newfstatat(2)`'s complete pointer,
/// lifetime, and accessibility requirements. `directory_fd` and `flags` are
/// passed directly to the kernel.
#[inline]
unsafe fn newfstatat(
    directory_fd: c_int,
    path: *const c_char,
    buffer: *mut Stat,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller upholds the exact raw newfstatat pointer contract.
    c_status(unsafe { raw_newfstatat(directory_fd, path, buffer, flags) })
}

/// Read the private stat record needed by an internal pathname client without
/// publishing an intermediate errno.
///
/// A sibling owns the resulting C error boundary, which lets it distinguish
/// dangling links and unreadable directories without exposing a second copy of
/// the x86 record layout.
///
/// # Safety
///
/// `path` must meet Linux `newfstatat(2)`'s pathname-pointer contract for the
/// syscall duration. The boolean selects ordinary following `stat` versus a
/// final-symlink-preserving `lstat` lookup.
#[inline(always)]
#[cfg(feature = "x86-filesystem-traversal")]
pub(super) unsafe fn path_metadata(
    path: *const c_char,
    follow_final_symlink: bool,
) -> Result<PathMetadata, c_int> {
    let mut record: Stat = unsafe { core::mem::zeroed() };
    let flags = if follow_final_symlink {
        0
    } else {
        AT_SYMLINK_NOFOLLOW
    };
    // SAFETY: the caller supplies the complete pathname contract and this
    // local owns a full private x86 output record.
    let result = unsafe {
        raw_newfstatat(
            AT_FDCWD,
            path,
            &mut record as *mut Stat,
            flags,
        )
    };
    if result < 0 && result >= -4_095 {
        Err(result.wrapping_neg() as c_int)
    } else {
        Ok(PathMetadata { record })
    }
}

/// Fill the x86 `struct stat` record for a pathname relative to the current
/// working directory.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname and `buffer` must
/// point to writable storage for one complete x86 `struct stat` record.
#[no_mangle]
pub unsafe extern "C" fn stat(path: *const c_char, buffer: *mut Stat) -> c_int {
    // SAFETY: this C entry point's documented caller obligations are exactly
    // the raw `newfstatat` pointer obligations.
    unsafe { newfstatat(AT_FDCWD, path, buffer, 0) }
}

/// Fill the x86 `struct stat` record for a pathname without following its
/// final symbolic link.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname and `buffer` must
/// point to writable storage for one complete x86 `struct stat` record.
#[no_mangle]
pub unsafe extern "C" fn lstat(path: *const c_char, buffer: *mut Stat) -> c_int {
    // SAFETY: this C entry point's documented caller obligations are exactly
    // the raw `newfstatat` pointer obligations.
    unsafe { newfstatat(AT_FDCWD, path, buffer, AT_SYMLINK_NOFOLLOW) }
}

/// Fill the x86 `struct stat` record for one open file descriptor.
///
/// # Safety
///
/// `buffer` must point to writable storage for one complete x86 `struct stat`
/// record. `file_descriptor` is passed directly to Linux `fstat(2)`.
#[no_mangle]
pub unsafe extern "C" fn fstat(file_descriptor: c_int, buffer: *mut Stat) -> c_int {
    // SAFETY: the C caller owns the descriptor and output-pointer contract.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FSTAT,
            i64::from(file_descriptor),
            buffer as usize as i64,
        )
    };
    c_status(result)
}

/// Read only the private x86 `st_mode` word for a descriptor-owning sibling.
///
/// This keeps `Stat`'s exact x86 layout and field ownership in this module
/// while allowing a selected C ABI leaf to validate a descriptor before it
/// assumes ownership. Unlike [`fstat`], this helper returns the raw Linux
/// errno to its sibling so that sibling can preserve its own C error boundary.
///
/// # Safety
///
/// `file_descriptor` must be a scalar descriptor value suitable for Linux
/// `fstat(2)`. The kernel validates descriptor liveness; the helper's local
/// output record is complete private writable storage for the syscall.
#[inline(always)]
pub(super) unsafe fn fstat_mode(file_descriptor: c_int) -> Result<u32, c_int> {
    // SAFETY: zero is a valid initial representation for the private x86
    // metadata record, which Linux fills on a successful fstat request.
    let mut metadata: Stat = unsafe { core::mem::zeroed() };
    // SAFETY: `metadata` is one complete private x86 output record and the
    // caller supplies the scalar descriptor contract.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FSTAT,
            i64::from(file_descriptor),
            (&mut metadata as *mut Stat) as usize as i64,
        )
    };
    if result < 0 && result >= -4_095 {
        Err(result.wrapping_neg() as c_int)
    } else {
        Ok(metadata.mode)
    }
}

/// Fill the x86 `struct stat` record for a pathname relative to
/// `directory_fd`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname and `buffer` must
/// point to writable storage for one complete x86 `struct stat` record.
/// `directory_fd` and `flags` are direct Linux `newfstatat(2)` arguments.
#[no_mangle]
pub unsafe extern "C" fn fstatat(
    directory_fd: c_int,
    path: *const c_char,
    buffer: *mut Stat,
    flags: c_int,
) -> c_int {
    // SAFETY: this C entry point's documented caller obligations are exactly
    // the raw `newfstatat` pointer obligations.
    unsafe { newfstatat(directory_fd, path, buffer, flags) }
}

/// Historical `stat` ABI spelling. The version is an ABI selector only; Linux
/// uses the one current x86 `struct stat` record selected above.
///
/// # Safety
///
/// Same as [`stat`].
#[no_mangle]
pub unsafe extern "C" fn __xstat(
    _version: c_int,
    path: *const c_char,
    buffer: *mut Stat,
) -> c_int {
    // SAFETY: forwarded unchanged to the ordinary C ABI boundary.
    unsafe { stat(path, buffer) }
}

/// Historical non-following `stat` ABI spelling.
///
/// # Safety
///
/// Same as [`lstat`].
#[no_mangle]
pub unsafe extern "C" fn __lxstat(
    _version: c_int,
    path: *const c_char,
    buffer: *mut Stat,
) -> c_int {
    // SAFETY: forwarded unchanged to the ordinary C ABI boundary.
    unsafe { lstat(path, buffer) }
}

/// Historical descriptor `stat` ABI spelling.
///
/// # Safety
///
/// Same as [`fstat`].
#[no_mangle]
pub unsafe extern "C" fn __fxstat(
    _version: c_int,
    file_descriptor: c_int,
    buffer: *mut Stat,
) -> c_int {
    // SAFETY: forwarded unchanged to the ordinary C ABI boundary.
    unsafe { fstat(file_descriptor, buffer) }
}

/// Historical descriptor-relative `stat` ABI spelling.
///
/// # Safety
///
/// Same as [`fstatat`].
#[no_mangle]
pub unsafe extern "C" fn __fxstatat(
    _version: c_int,
    directory_fd: c_int,
    path: *const c_char,
    buffer: *mut Stat,
    flags: c_int,
) -> c_int {
    // SAFETY: forwarded unchanged to the ordinary C ABI boundary.
    unsafe { fstatat(directory_fd, path, buffer, flags) }
}
