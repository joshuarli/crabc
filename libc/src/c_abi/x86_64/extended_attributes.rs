//! Selected static Linux/x86-64 C extended-attribute boundary.
//!
//! This leaf owns the complete Linux path, no-follow-path, and descriptor
//! xattr syscall surface: `setxattr`, `lsetxattr`, `fsetxattr`, `getxattr`,
//! `lgetxattr`, `fgetxattr`, `listxattr`, `llistxattr`, `flistxattr`,
//! `removexattr`, `lremovexattr`, and `fremovexattr`. It passes every pathname,
//! attribute name, value/list buffer, size, descriptor, and flag word directly
//! to Linux; the kernel remains authoritative for filesystem support, xattr
//! namespaces, name and value limits, flags, and resolution races. This leaf
//! owns no path policy, allocation, retry, cancellation point, libc.so, CRT,
//! loader, sysroot, or public x86 support.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//!
//! - `src/linux/xattr.c` maps its twelve one-syscall functions directly to
//!   the correspondingly named entries in this file.
//!
//! Musl likewise uses ordinary `syscall(...)`, not its cancellation-point
//! machinery. Linux 5.10 provides all twelve legacy xattr requests. The
//! shared syscall table records the Linux/x86-64 UAPI values. Raw Linux errors
//! pass through the selected initial-TLS C `errno` translation without a
//! fallback or userspace policy.

use core::ffi::{c_char, c_int, c_void};

use super::{c_ssize_status, c_status, raw_syscall};

/// Set an extended attribute while following `path`'s final symlink.
///
/// # Safety
///
/// `path` and `name` must point to readable NUL-terminated strings for the
/// syscall duration. When `size` is nonzero, `value` must point to `size`
/// readable bytes; a null `value` is permitted for a zero-size attribute.
/// The caller owns pathname-resolution races, descriptor-independent
/// filesystem authority, and the raw Linux flag-word contract.
#[no_mangle]
pub unsafe extern "C" fn setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller owns each pathname/name/value lifetime and the raw
    // flag contract; syscall5 puts `size` and `flags` in r10 and r8.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_SETXATTR,
            path as usize as i64,
            name as usize as i64,
            value as usize as i64,
            size as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Set an extended attribute without following `path`'s final symlink.
///
/// # Safety
///
/// `path` and `name` must point to readable NUL-terminated strings for the
/// syscall duration. When `size` is nonzero, `value` must point to `size`
/// readable bytes; a null `value` is permitted for a zero-size attribute.
/// The caller owns pathname-resolution races, filesystem authority, and the
/// raw Linux flag-word contract.
#[no_mangle]
pub unsafe extern "C" fn lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller owns each pathname/name/value lifetime and the raw
    // flag contract; syscall5 puts `size` and `flags` in r10 and r8.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_LSETXATTR,
            path as usize as i64,
            name as usize as i64,
            value as usize as i64,
            size as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Set an extended attribute on an open descriptor.
///
/// # Safety
///
/// `name` must point to a readable NUL-terminated string for the syscall
/// duration. When `size` is nonzero, `value` must point to `size` readable
/// bytes; a null `value` is permitted for a zero-size attribute. The caller
/// owns descriptor lifetime, filesystem authority, and the raw Linux
/// flag-word contract.
#[no_mangle]
pub unsafe extern "C" fn fsetxattr(
    descriptor: c_int,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller owns descriptor/name/value validity and the raw flag
    // contract; syscall5 puts `size` and `flags` in r10 and r8.
    let result = unsafe {
        raw_syscall::syscall5(
            raw_syscall::SYS_FSETXATTR,
            i64::from(descriptor),
            name as usize as i64,
            value as usize as i64,
            size as i64,
            i64::from(flags),
        )
    };
    c_status(result)
}

/// Read an extended attribute while following `path`'s final symlink.
///
/// # Safety
///
/// `path` and `name` must point to readable NUL-terminated strings for the
/// syscall duration. When `size` is nonzero, `value` must point to `size`
/// writable bytes; a null `value` is permitted for the zero-size length query.
/// The caller owns pathname-resolution races and filesystem authority.
#[no_mangle]
pub unsafe extern "C" fn getxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    // SAFETY: the caller owns pathname/name/output-buffer validity; syscall4
    // puts the output size in Linux x86-64's r10 argument register.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_GETXATTR,
            path as usize as i64,
            name as usize as i64,
            value as usize as i64,
            size as i64,
        )
    };
    c_ssize_status(result)
}

/// Read an extended attribute without following `path`'s final symlink.
///
/// # Safety
///
/// `path` and `name` must point to readable NUL-terminated strings for the
/// syscall duration. When `size` is nonzero, `value` must point to `size`
/// writable bytes; a null `value` is permitted for the zero-size length query.
/// The caller owns pathname-resolution races and filesystem authority.
#[no_mangle]
pub unsafe extern "C" fn lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    // SAFETY: the caller owns pathname/name/output-buffer validity; syscall4
    // puts the output size in Linux x86-64's r10 argument register.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_LGETXATTR,
            path as usize as i64,
            name as usize as i64,
            value as usize as i64,
            size as i64,
        )
    };
    c_ssize_status(result)
}

/// Read an extended attribute from an open descriptor.
///
/// # Safety
///
/// `name` must point to a readable NUL-terminated string for the syscall
/// duration. When `size` is nonzero, `value` must point to `size` writable
/// bytes; a null `value` is permitted for the zero-size length query. The
/// caller owns descriptor lifetime and filesystem authority.
#[no_mangle]
pub unsafe extern "C" fn fgetxattr(
    descriptor: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    // SAFETY: the caller owns descriptor/name/output-buffer validity;
    // syscall4 puts the output size in Linux x86-64's r10 register.
    let result = unsafe {
        raw_syscall::syscall4(
            raw_syscall::SYS_FGETXATTR,
            i64::from(descriptor),
            name as usize as i64,
            value as usize as i64,
            size as i64,
        )
    };
    c_ssize_status(result)
}

/// List `path`'s attribute names while following its final symlink.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the syscall
/// duration. When `size` is nonzero, `list` must point to `size` writable
/// bytes; a null `list` is permitted for the zero-size length query. The
/// caller owns pathname-resolution races and filesystem authority.
#[no_mangle]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    // SAFETY: the caller owns pathname/output-buffer validity; syscall3
    // forwards the x86-64 Linux machine words unchanged.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LISTXATTR,
            path as usize as i64,
            list as usize as i64,
            size as i64,
        )
    };
    c_ssize_status(result)
}

/// List `path`'s attribute names without following its final symlink.
///
/// # Safety
///
/// `path` must point to a readable NUL-terminated string for the syscall
/// duration. When `size` is nonzero, `list` must point to `size` writable
/// bytes; a null `list` is permitted for the zero-size length query. The
/// caller owns pathname-resolution races and filesystem authority.
#[no_mangle]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    // SAFETY: the caller owns pathname/output-buffer validity; syscall3
    // forwards the x86-64 Linux machine words unchanged.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_LLISTXATTR,
            path as usize as i64,
            list as usize as i64,
            size as i64,
        )
    };
    c_ssize_status(result)
}

/// List attribute names from an open descriptor.
///
/// # Safety
///
/// When `size` is nonzero, `list` must point to `size` writable bytes; a null
/// `list` is permitted for the zero-size length query. The caller owns
/// descriptor lifetime and filesystem authority.
#[no_mangle]
pub unsafe extern "C" fn flistxattr(descriptor: c_int, list: *mut c_char, size: usize) -> isize {
    // SAFETY: the caller owns descriptor/output-buffer validity; syscall3
    // forwards the x86-64 Linux machine words unchanged.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_FLISTXATTR,
            i64::from(descriptor),
            list as usize as i64,
            size as i64,
        )
    };
    c_ssize_status(result)
}

/// Remove an extended attribute while following `path`'s final symlink.
///
/// # Safety
///
/// `path` and `name` must point to readable NUL-terminated strings for the
/// syscall duration. The caller owns pathname-resolution races and filesystem
/// authority.
#[no_mangle]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    // SAFETY: the caller owns pathname/name validity for Linux's two-word
    // x86-64 syscall contract.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_REMOVEXATTR,
            path as usize as i64,
            name as usize as i64,
        )
    };
    c_status(result)
}

/// Remove an extended attribute without following `path`'s final symlink.
///
/// # Safety
///
/// `path` and `name` must point to readable NUL-terminated strings for the
/// syscall duration. The caller owns pathname-resolution races and filesystem
/// authority.
#[no_mangle]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    // SAFETY: the caller owns pathname/name validity for Linux's two-word
    // x86-64 syscall contract.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_LREMOVEXATTR,
            path as usize as i64,
            name as usize as i64,
        )
    };
    c_status(result)
}

/// Remove an extended attribute from an open descriptor.
///
/// # Safety
///
/// `name` must point to a readable NUL-terminated string for the syscall
/// duration. The caller owns descriptor lifetime and filesystem authority.
#[no_mangle]
pub unsafe extern "C" fn fremovexattr(descriptor: c_int, name: *const c_char) -> c_int {
    // SAFETY: the caller owns descriptor/name validity for Linux's two-word
    // x86-64 syscall contract.
    let result = unsafe {
        raw_syscall::syscall2(
            raw_syscall::SYS_FREMOVEXATTR,
            i64::from(descriptor),
            name as usize as i64,
        )
    };
    c_status(result)
}
