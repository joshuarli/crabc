//! Private Linux/x86-64 file-handle C ABI pair.
//!
//! This module preserves pinned musl 1.2.6 `src/linux/name_to_handle_at.c`
//! and `src/linux/open_by_handle_at.c`: each entry forwards its caller-owned
//! arguments directly to Linux 5.10 syscall 303 or 304.  The C
//! `struct file_handle` is deliberately represented as opaque storage here;
//! its variable-sized `f_handle[]` tail, capacity, type, and mount-id output
//! remain owned and validated by the caller/kernel contract.  This is a
//! private opt-in filesystem extension, not handle allocation, pathname
//! policy, mount authority, allocator support, a Rust facade, or public x86
//! support.
//!
//! The x86-64 syscall ABI differs from the SysV C ABI for argument four: the
//! raw boundary moves it from C `rcx` to `r10`; the fifth word remains in
//! `r8`.  `c_status` alone translates Linux's negative errno result and
//! publishes the selected initial-TLS C `errno` slot.

use core::ffi::{c_char, c_int, c_void};

use super::{c_status, raw_syscall};

/// Ask the filesystem for its opaque handle for one caller-owned pathname.
///
/// # Safety
///
/// `pathname` must point to a readable NUL-terminated path for the syscall.
/// When non-null, `handle` must point to writable storage whose leading
/// `handle_bytes` field describes the available variable-sized tail; when
/// non-null, `mount_id` must point to writable `c_int` storage.  The caller
/// owns the lifetime, alignment, capacity, and interpretation of that
/// storage, as well as all path, mount, and flag semantics.
#[no_mangle]
pub unsafe extern "C" fn name_to_handle_at(
    directory_descriptor: c_int,
    pathname: *const c_char,
    handle: *mut c_void,
    mount_id: *mut c_int,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller upholds the Linux pathname, variable-sized handle,
    // mount-id, descriptor, and flag contracts documented above. The raw
    // x86-64 boundary places words in rdi/rsi/rdx/r10/r8.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_NAME_TO_HANDLE_AT,
            i64::from(directory_descriptor),
            pathname as usize as i64,
            handle as usize as i64,
            mount_id as usize as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Reopen one caller-owned opaque filesystem handle relative to a mount fd.
///
/// # Safety
///
/// `handle` must point to a valid variable-sized `struct file_handle` for the
/// duration of the call.  The caller owns its storage/lifetime and the mount
/// descriptor, capability/permission requirements, and meaning of `flags`.
/// The entry performs no validation or policy beyond Linux's syscall ABI.
#[no_mangle]
pub unsafe extern "C" fn open_by_handle_at(
    mount_descriptor: c_int,
    handle: *mut c_void,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller upholds the Linux opaque-handle, mount descriptor,
    // and flag contracts documented above. The raw x86-64 boundary places
    // words in rdi/rsi/rdx.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_OPEN_BY_HANDLE_AT,
            i64::from(mount_descriptor),
            handle as usize as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}
