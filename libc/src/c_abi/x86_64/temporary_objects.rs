//! Atomic temporary-object creation for the installed runtime.
//!
//! Pinned musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT):
//! `src/temp/{mkostemps,mkostemp,mkstemps,mkstemp,mkdtemp}.c` map to the
//! corresponding entries here. `create` retains their six-X validation,
//! 100-collision retry, exclusive creation, and failed-template restoration.
//! File creation uses the existing `descriptor_entry::open` owner; directory
//! creation uses Linux mkdir. Neither returns an unreserved candidate name.
//!
//! The shared `temp_name_random` helper retains the source's time/TID name
//! arithmetic, not cryptographic randomness. Its documented raw-clock/TID
//! fail-closed difference and the current open cancellation limitation apply.
//! Callers own returned descriptors/directories and their eventual removal.

use core::ffi::{c_char, c_int};
use super::{c_status, descriptor_entry, errno, raw_syscall, temp_name_random};

const EINVAL: c_int = 22;
const EEXIST: c_int = 17;
const O_ACCMODE: c_int = 3;
const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0x40;
const O_EXCL: c_int = 0x80;

enum Object { File(c_int), Directory }

/// Caller owns a writable NUL-terminated template throughout this operation.
unsafe fn create(template: *mut c_char, suffix_length: c_int, object: Object) -> c_int {
    let mut length = 0usize;
    while unsafe { *template.add(length) } != 0 { length += 1; }
    if length < 6 || suffix_length < 0 || suffix_length as usize > length - 6 {
        unsafe { errno::set_errno(EINVAL); }
        return -1;
    }
    let suffix = unsafe { template.add(length - suffix_length as usize - 6).cast::<u8>() };
    for index in 0..6 {
        if unsafe { *suffix.add(index) } != b'X' {
            unsafe { errno::set_errno(EINVAL); }
            return -1;
        }
    }
    for _ in 0..100 {
        if let Err(error) = unsafe { temp_name_random::randomize_suffix(suffix) } {
            unsafe { errno::set_errno(error); }
            break;
        }
        let result = match object {
            Object::File(flags) => unsafe {
                descriptor_entry::open(template, (flags & !O_ACCMODE) | O_RDWR | O_CREAT | O_EXCL, 0o600)
            },
            Object::Directory => c_status(unsafe {
                raw_syscall::syscall2(raw_syscall::SYS_MKDIR, template as usize as i64, 0o700)
            }),
        };
        if result >= 0 { return result; }
        if unsafe { errno::get_errno() } != EEXIST { break; }
    }
    unsafe { core::ptr::write_bytes(suffix, b'X', 6); }
    -1
}

/// Create an exclusive read/write file, preserving a trailing suffix.
///
/// # Safety
/// `template` must be writable NUL-terminated storage, exclusively borrowed
/// for the call. Its six `X` bytes preceding `suffix_length` are replaced on
/// success; the caller must close the returned descriptor and remove the file.
#[no_mangle]
pub unsafe extern "C" fn mkostemps(template: *mut c_char, suffix_length: c_int, flags: c_int) -> c_int {
    unsafe { create(template, suffix_length, Object::File(flags)) }
}

/// Create an exclusive file from a template ending in six `X` bytes.
///
/// # Safety
/// `template` must be writable NUL-terminated storage exclusively borrowed
/// for this call. The caller owns the returned descriptor and created pathname.
#[no_mangle]
pub unsafe extern "C" fn mkostemp(template: *mut c_char, flags: c_int) -> c_int {
    unsafe { create(template, 0, Object::File(flags)) }
}

/// Create an exclusive read/write file with a preserved trailing suffix.
///
/// # Safety
/// `template` must be writable NUL-terminated storage exclusively borrowed
/// for this call. The caller owns the returned descriptor and created pathname.
#[no_mangle]
pub unsafe extern "C" fn mkstemps(template: *mut c_char, suffix_length: c_int) -> c_int {
    unsafe { create(template, suffix_length, Object::File(0)) }
}

/// Create an exclusive mode-0600 file from a six-X template.
///
/// # Safety
/// `template` must be writable NUL-terminated storage exclusively borrowed
/// for this call. The caller owns the returned descriptor and created pathname.
#[no_mangle]
pub unsafe extern "C" fn mkstemp(template: *mut c_char) -> c_int {
    unsafe { create(template, 0, Object::File(0)) }
}

/// Create an exclusive mode-0700 directory from a six-X template.
///
/// # Safety
/// `template` must be writable NUL-terminated storage exclusively borrowed
/// for this call. Success returns that same buffer; the caller owns removal
/// of the newly created directory and must retain the name for later use.
#[no_mangle]
pub unsafe extern "C" fn mkdtemp(template: *mut c_char) -> *mut c_char {
    if unsafe { create(template, 0, Object::Directory) } == 0 { template }
    else { core::ptr::null_mut() }
}
