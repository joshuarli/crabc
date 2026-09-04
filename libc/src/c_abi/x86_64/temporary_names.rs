//! Linux/x86-64 legacy C temporary-name compatibility.
//!
//! This module is a provenance-preserving translation of pinned musl 1.2.6
//! release commit 9fa28ece75d8a2191de7c5bb53bed224c5947417, under musl's MIT
//! license:
//!
//! - src/stdio/tmpnam.c::tmpnam maps to [tmpnam].
//! - src/stdio/tempnam.c::tempnam maps to [tempnam].
//! - src/temp/__randname.c::__randname maps to the shared
//!   [super::temp_name_random::randomize_suffix] helper.
//!
//! Both public entries generate a pathname and use raw readlink=89 only to
//! observe whether that exact pathname is absent. The legacy surface does not create, open, reserve, or unlink
//! it, so both are inherently racy and make no security,
//! uniqueness, descriptor, or ownership guarantee for the pathname itself.
//! tmpnam(NULL) retains musl's process-global static 20-byte result buffer;
//! callers must externally serialize access to that buffer. tempnam returns a
//! separately allocator-owned string through the already evidenced strdup
//! client boundary, and callers release a non-null result through the matching
//! C free ABI.
//!
//! The shared x86 __randname adaptation deliberately uses raw clock_gettime
//! and gettid instead of musl's VDSO-first clock path and pthread TCB tid.
//! Seccomp can therefore select this target-local fail-closed branch where
//! musl might still produce a suffix. The candidate returns NULL and publishes
//! the raw error rather than deriving a name from invalid time storage; musl's
//! source ignores a failed __clock_gettime observation and has no useful
//! defined suffix result on that exceptional path.

use core::ffi::{c_char, c_int};
use core::ptr;

use super::{errno, raw_syscall, temp_name_random};

const MAX_ATTEMPTS: usize = 100;
const L_TMPNAM: usize = 20;
const PATH_MAX: usize = 4096;
const ENAMETOOLONG: c_int = 36;
const ENOENT: c_int = 2;
const TMPNAM_TEMPLATE_PREFIX_BYTES: usize = 12;
const DEFAULT_DIRECTORY: &[u8] = b"/tmp\0";
const DEFAULT_PREFIX: &[u8] = b"temp\0";

static mut TMPNAM_INTERNAL: [c_char; L_TMPNAM] = [0; L_TMPNAM];

// Do not make a Rust-level dependency on the private allocation-client
// module. The selected feature archive records this as the public strdup
// dependency, so evidence can prove that the existing allocator baseline,
// rather than pinned musl, owns returned storage.
unsafe extern "C" {
    #[link_name = "strdup"]
    fn cabi_strdup(source: *const c_char) -> *mut c_char;
}

/// Return the length of one caller-owned NUL-terminated C string.
///
/// # Safety
///
/// text must point to a readable NUL-terminated C string for the complete
/// scan. This preserves the C API's pointer and extent obligation rather than
/// adding a Rust path or encoding policy.
#[inline]
unsafe fn c_string_length(text: *const c_char) -> usize {
    let mut length = 0_usize;
    while unsafe { ptr::read(text.add(length)) } != 0 {
        length += 1;
    }
    length
}

/// Copy a known byte sequence into caller-owned C storage.
///
/// # Safety
///
/// destination must designate at least byte_count writable bytes and source
/// must designate that many readable bytes. The count includes the final NUL
/// byte when one is required by the C result.
#[inline]
unsafe fn copy_bytes(destination: *mut c_char, source: *const u8, byte_count: usize) {
    for index in 0..byte_count {
        // SAFETY: the helper contract retains both source and destination
        // bytes for every bounded iteration.
        unsafe {
            ptr::write(
                destination.cast::<u8>().add(index),
                ptr::read(source.add(index)),
            )
        };
    }
}

/// Observe whether one NUL-terminated pathname is currently absent.
///
/// The source intentionally uses one-byte readlink output storage rather than
/// stat, access, or open. A result other than raw -ENOENT is not converted to
/// C errno and simply leaves the caller in the source-selected retry loop.
///
/// # Safety
///
/// pathname must be a readable NUL-terminated pathname for the raw Linux
/// syscall.
#[inline]
unsafe fn pathname_is_absent(pathname: *const c_char) -> bool {
    let mut output = [0_u8; 1];
    // SAFETY: the caller supplies the complete pathname; output is one
    // writable byte exactly as the musl source's compound literal.
    let result = unsafe {
        raw_syscall::syscall3(
            raw_syscall::SYS_READLINK,
            pathname as usize as i64,
            output.as_mut_ptr() as usize as i64,
            1,
        )
    };
    result == -i64::from(ENOENT)
}

/// Generate a legacy temporary pathname in an explicit caller buffer or the
/// source-compatible internal static buffer.
///
/// # Safety
///
/// When non-null, buffer must address at least L_tmpnam writable bytes.
/// Callers using NULL must externally serialize all access to the returned
/// process-global buffer, including later reads and writes. This function only
/// returns a racy absent pathname; it does not reserve or create it.
#[no_mangle]
pub unsafe extern "C" fn tmpnam(buffer: *mut c_char) -> *mut c_char {
    let mut template = *b"/tmp/tmpnam_XXXXXX\0";
    for _ in 0..MAX_ATTEMPTS {
        // SAFETY: the fixed template holds exactly six writable suffix bytes.
        if let Err(error) = unsafe {
            temp_name_random::randomize_suffix(
                template
                    .as_mut_ptr()
                    .wrapping_add(TMPNAM_TEMPLATE_PREFIX_BYTES),
            )
        } {
            // SAFETY: this target-local fail-closed branch owns only the
            // selected initial-TLS C errno result.
            unsafe { errno::set_errno(error) };
            return ptr::null_mut();
        }
        // SAFETY: the local template remains NUL-terminated for this probe.
        if unsafe { pathname_is_absent(template.as_ptr().cast::<c_char>()) } {
            let destination = if buffer.is_null() {
                // SAFETY: this forms only a raw pointer to the static storage,
                // avoiding a Rust shared reference to mutable global state.
                core::ptr::addr_of_mut!(TMPNAM_INTERNAL).cast::<c_char>()
            } else {
                buffer
            };
            // SAFETY: the API contract reserves L_tmpnam output bytes; the
            // fixed template's 19 bytes include its NUL terminator.
            unsafe { copy_bytes(destination, template.as_ptr(), template.len()) };
            return destination;
        }
    }
    ptr::null_mut()
}

/// Generate an allocator-owned legacy temporary pathname.
///
/// # Safety
///
/// Each non-null argument must point to a readable NUL-terminated C string.
/// A non-null result is allocated through the selected C strdup boundary and
/// must be released through the corresponding C free ABI. The caller retains
/// all filesystem and later pathname-use synchronization obligations: this
/// function only observes a racy absent name and never creates or reserves it.
#[no_mangle]
pub unsafe extern "C" fn tempnam(
    directory: *const c_char,
    prefix: *const c_char,
) -> *mut c_char {
    let directory = if directory.is_null() {
        DEFAULT_DIRECTORY.as_ptr().cast::<c_char>()
    } else {
        directory
    };
    let prefix = if prefix.is_null() {
        DEFAULT_PREFIX.as_ptr().cast::<c_char>()
    } else {
        prefix
    };
    // SAFETY: the public C caller supplies complete readable strings or
    // selects these local NUL-terminated defaults.
    let directory_length = unsafe { c_string_length(directory) };
    // SAFETY: the public C caller supplies a complete readable prefix or the
    // local default supplies one.
    let prefix_length = unsafe { c_string_length(prefix) };
    let Some(path_length) = directory_length
        .checked_add(1)
        .and_then(|length| length.checked_add(prefix_length))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(temp_name_random::TEMPLATE_SUFFIX_BYTES))
    else {
        // SAFETY: representational overflow cannot construct a source-valid
        // PATH_MAX candidate, so publish the same length error.
        unsafe { errno::set_errno(ENAMETOOLONG) };
        return ptr::null_mut();
    };
    if path_length >= PATH_MAX {
        // SAFETY: this C ABI leaf owns its source-selected length error.
        unsafe { errno::set_errno(ENAMETOOLONG) };
        return ptr::null_mut();
    }

    let mut template = [0_u8; PATH_MAX];
    // SAFETY: path_length's checked construction leaves the full directory
    // byte range and its separating slash inside the fixed local array.
    unsafe {
        copy_bytes(
            template.as_mut_ptr().cast::<c_char>(),
            directory.cast::<u8>(),
            directory_length,
        )
    };
    // SAFETY: path_length includes this separator and is strictly below
    // PATH_MAX, so the checked construction retains this byte in template.
    unsafe { ptr::write(template.as_mut_ptr().add(directory_length), b'/') };
    // SAFETY: the checked path length retains this complete prefix range.
    unsafe {
        copy_bytes(
            template
                .as_mut_ptr()
                .wrapping_add(directory_length + 1)
                .cast::<c_char>(),
            prefix.cast::<u8>(),
            prefix_length,
        )
    };
    // SAFETY: both the separator-adjacent underscore and trailing NUL lie
    // inside the source-valid checked path length.
    unsafe {
        ptr::write(
            template
                .as_mut_ptr()
                .add(directory_length + 1 + prefix_length),
            b'_',
        );
        ptr::write(template.as_mut_ptr().add(path_length), 0);
    }
    let suffix = template
        .as_mut_ptr()
        // path_length includes the fixed six-byte suffix by construction.
        .wrapping_add(path_length.wrapping_sub(temp_name_random::TEMPLATE_SUFFIX_BYTES));

    for _ in 0..MAX_ATTEMPTS {
        // SAFETY: path_length reserves exactly the final six writable bytes.
        if let Err(error) = unsafe { temp_name_random::randomize_suffix(suffix) } {
            // SAFETY: see the module-level documented fail-closed difference.
            unsafe { errno::set_errno(error) };
            return ptr::null_mut();
        }
        // SAFETY: the local template remains NUL-terminated for this probe.
        if unsafe { pathname_is_absent(template.as_ptr().cast::<c_char>()) } {
            // SAFETY: the selected feature baseline supplies the public C
            // strdup ABI and owns allocation failure and returned storage.
            return unsafe { cabi_strdup(template.as_ptr().cast::<c_char>()) };
        }
    }
    ptr::null_mut()
}

/// Link-time witness for the opt-in legacy temporary-name object.
///
/// This private evidence glue lets the native runner prove that both public
/// names share exactly one crate-owned object without exposing another public
/// header callable.
#[no_mangle]
pub extern "C" fn __crabc_x86_temporary_names_v1() -> usize {
    1
}
