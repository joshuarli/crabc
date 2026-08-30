//! Selected static Linux/x86-64 filesystem-capacity C ABI boundary.
//!
//! This leaf owns the direct Linux `statfs(2)`/`fstatfs(2)` record calls and
//! musl's derived `statvfs(3)`/`fstatvfs(3)` view for the x86-64 LP64 ABI.
//! The kernel fills `StatFs` directly through `statfs=137` or `fstatfs=138`;
//! the `StatVfs` calls use a private kernel record and reproduce musl's
//! field-by-field conversion, including the first `f_fsid` word rule and the
//! zero-`f_frsize` fallback. All four calls use ordinary C `-1`/`errno`
//! translation. This is not filesystem policy, pathname handling, allocator,
//! CRT, pthread/TLS lifecycle beyond the already-selected initial `errno`
//! slot, loader, sysroot, libc.so, or public x86-64 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/stat/statvfs.c` maps its `__statfs`/`__fstatfs` weak aliases to
//!   [`statfs`]/[`fstatfs`] over the Linux x86-64 syscall ABI, and its
//!   `statvfs`/`fstatvfs` bodies to [`statvfs`]/[`fstatvfs`] plus
//!   [`statvfs_from_statfs`].

use core::ffi::{c_char, c_int, c_uint, c_ulong};
use core::mem::{align_of, offset_of, size_of};

use super::{c_status, raw_syscall};

/// Exact Linux/x86-64 LP64 `struct statfs` record.
///
/// Public spelling and visibility remain owned by `include/sys/statfs.h`; the
/// selected static leaf keeps the Rust representation private so it cannot
/// widen the staged C ABI beyond these four admitted entry points.
#[repr(C)]
pub(super) struct StatFs {
    filesystem_type: c_ulong,
    block_size: c_ulong,
    blocks: u64,
    blocks_free: u64,
    blocks_available: u64,
    files: u64,
    files_free: u64,
    filesystem_id: [c_int; 2],
    maximum_name_length: c_ulong,
    fragment_size: c_ulong,
    flags: c_ulong,
    spare: [c_ulong; 4],
}

/// Exact project x86 LP64 `struct statvfs` record.
#[repr(C)]
pub(super) struct StatVfs {
    block_size: c_ulong,
    fragment_size: c_ulong,
    blocks: u64,
    blocks_free: u64,
    blocks_available: u64,
    files: u64,
    files_free: u64,
    files_available: u64,
    filesystem_id: c_ulong,
    flags: c_ulong,
    maximum_name_length: c_ulong,
    filesystem_type: c_uint,
    reserved: [c_int; 5],
}

const _: () = {
    assert!(size_of::<StatFs>() == 120);
    assert!(align_of::<StatFs>() == 8);
    assert!(offset_of!(StatFs, filesystem_type) == 0);
    assert!(offset_of!(StatFs, block_size) == 8);
    assert!(offset_of!(StatFs, blocks) == 16);
    assert!(offset_of!(StatFs, blocks_free) == 24);
    assert!(offset_of!(StatFs, blocks_available) == 32);
    assert!(offset_of!(StatFs, files) == 40);
    assert!(offset_of!(StatFs, files_free) == 48);
    assert!(offset_of!(StatFs, filesystem_id) == 56);
    assert!(offset_of!(StatFs, maximum_name_length) == 64);
    assert!(offset_of!(StatFs, fragment_size) == 72);
    assert!(offset_of!(StatFs, flags) == 80);
    assert!(offset_of!(StatFs, spare) == 88);

    assert!(size_of::<StatVfs>() == 112);
    assert!(align_of::<StatVfs>() == 8);
    assert!(offset_of!(StatVfs, block_size) == 0);
    assert!(offset_of!(StatVfs, fragment_size) == 8);
    assert!(offset_of!(StatVfs, blocks) == 16);
    assert!(offset_of!(StatVfs, files) == 40);
    assert!(offset_of!(StatVfs, filesystem_id) == 64);
    assert!(offset_of!(StatVfs, flags) == 72);
    assert!(offset_of!(StatVfs, maximum_name_length) == 80);
    assert!(offset_of!(StatVfs, filesystem_type) == 88);
    assert!(offset_of!(StatVfs, reserved) == 92);
};

#[inline]
unsafe fn statfs_raw(path: *const c_char, output: *mut StatFs) -> i64 {
    // SAFETY: the C caller owns Linux's pathname and output-buffer contracts.
    unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_STATFS,
            path as usize as i64,
            output as usize as i64,
        )
    }
}

#[inline]
unsafe fn fstatfs_raw(descriptor: c_int, output: *mut StatFs) -> i64 {
    // SAFETY: the C caller owns the descriptor and output-buffer contracts.
    unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FSTATFS,
            i64::from(descriptor),
            output as usize as i64,
        )
    }
}

/// Fill one Linux/x86-64 `struct statfs` record for `path`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname and `output` must
/// point to writable storage for one complete Linux/x86-64 `struct statfs`.
#[no_mangle]
pub unsafe extern "C" fn statfs(path: *const c_char, output: *mut StatFs) -> c_int {
    // SAFETY: musl clears every public byte first; caller owns the full writable
    // output record and raw pathname contract.
    unsafe { core::ptr::write_bytes(output, 0, 1) };
    c_status(unsafe { statfs_raw(path, output) })
}

/// Fill one Linux/x86-64 `struct statfs` record for `descriptor`.
///
/// # Safety
///
/// `descriptor` must remain valid for the call and `output` must point to
/// writable storage for one complete Linux/x86-64 `struct statfs`.
#[no_mangle]
pub unsafe extern "C" fn fstatfs(descriptor: c_int, output: *mut StatFs) -> c_int {
    // SAFETY: musl clears every public byte first; caller owns the full writable
    // output record and raw descriptor contract.
    unsafe { core::ptr::write_bytes(output, 0, 1) };
    c_status(unsafe { fstatfs_raw(descriptor, output) })
}

/// Reproduce musl's Linux `statfs` to public `statvfs` field conversion.
///
/// The caller provides a valid output record. `write_bytes` first gives the
/// private reserved tail musl's all-zero representation before named fields
/// are populated from the just-filled kernel record.
#[inline]
unsafe fn statvfs_from_statfs(output: *mut StatVfs, source: *const StatFs) {
    // SAFETY: the caller supplies one writable output record and one initialized
    // kernel record. Both representations are local `repr(C)` x86 layouts.
    unsafe {
        core::ptr::write_bytes(output, 0, 1);
        (*output).block_size = (*source).block_size;
        (*output).fragment_size = if (*source).fragment_size != 0 {
            (*source).fragment_size
        } else {
            (*source).block_size
        };
        (*output).blocks = (*source).blocks;
        (*output).blocks_free = (*source).blocks_free;
        (*output).blocks_available = (*source).blocks_available;
        (*output).files = (*source).files;
        (*output).files_free = (*source).files_free;
        (*output).files_available = (*source).files_free;
        (*output).filesystem_id = (*source).filesystem_id[0] as c_ulong;
        (*output).flags = (*source).flags;
        (*output).maximum_name_length = (*source).maximum_name_length;
        (*output).filesystem_type = (*source).filesystem_type as c_uint;
    }
}

/// Fill the derived `struct statvfs` view for `path`.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated pathname and `output` must
/// point to writable storage for one complete x86-64 `struct statvfs`.
#[no_mangle]
pub unsafe extern "C" fn statvfs(path: *const c_char, output: *mut StatVfs) -> c_int {
    // SAFETY: a zeroed kernel record is a valid output buffer for Linux.
    let mut kernel: StatFs = unsafe { core::mem::zeroed() };
    // SAFETY: the caller owns the pathname contract; `kernel` is writable.
    let result = unsafe { statfs_raw(path, &mut kernel) };
    if c_status(result) < 0 {
        return -1;
    }
    // SAFETY: a successful kernel call initialized `kernel`; caller owns output.
    unsafe { statvfs_from_statfs(output, &kernel) };
    0
}

/// Fill the derived `struct statvfs` view for `descriptor`.
///
/// # Safety
///
/// `descriptor` must remain valid for the call and `output` must point to
/// writable storage for one complete x86-64 `struct statvfs`.
#[no_mangle]
pub unsafe extern "C" fn fstatvfs(descriptor: c_int, output: *mut StatVfs) -> c_int {
    // SAFETY: a zeroed kernel record is a valid output buffer for Linux.
    let mut kernel: StatFs = unsafe { core::mem::zeroed() };
    // SAFETY: the caller owns the descriptor contract; `kernel` is writable.
    let result = unsafe { fstatfs_raw(descriptor, &mut kernel) };
    if c_status(result) < 0 {
        return -1;
    }
    // SAFETY: a successful kernel call initialized `kernel`; caller owns output.
    unsafe { statvfs_from_statfs(output, &kernel) };
    0
}
