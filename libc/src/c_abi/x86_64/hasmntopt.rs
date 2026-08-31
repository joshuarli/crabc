//! Selected static Linux/x86-64 `hasmntopt` C ABI boundary.
//!
//! This private compatibility leaf owns only the caller-buffer option-token
//! scan behind `char *hasmntopt(const struct mntent *, const char *)`. It does
//! not open, parse, cache, or otherwise observe an mtab file; callers retain
//! ownership of the complete writable `struct mntent` and NUL-terminated
//! `mnt_opts` byte string. There is no mount, unmount, filesystem, stdio,
//! errno, TLS, allocation, locale, lock, syscall, or runtime-state boundary.
//!
//! Translation provenance is pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
//! `src/misc/mntent.c::hasmntopt` maps directly to [`hasmntopt`]. Musl first
//! compares `opt` at the start of `mnt_opts` and each byte after a comma, then
//! accepts only an exact end, comma, or `=` suffix. The local byte walks keep
//! musl's `strlen`, `strncmp`, and `strchr` behavior in this one archive
//! member without selecting separate string helpers or an ambient libc.
//!
//! The Linux/x86-64 SysV ABI passes the two pointers in rdi/rsi and returns
//! either the matching mutable byte pointer or NULL in rax. `struct mntent`
//! remains its six-field 40-byte, align-8 LP64 C record. Invalid pointers or
//! unterminated input have the same outside-the-C-contract status as musl;
//! this leaf does not add validation or manufacture errno results.

use core::ffi::{c_char, c_int};

/// Linux/x86-64 C `struct mntent` record used only at this caller boundary.
#[repr(C)]
pub struct MntEnt {
    filesystem_name: *mut c_char,
    directory: *mut c_char,
    filesystem_type: *mut c_char,
    options: *mut c_char,
    frequency: c_int,
    pass_number: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<MntEnt>() == 40);
    assert!(core::mem::align_of::<MntEnt>() == 8);
    assert!(core::mem::offset_of!(MntEnt, filesystem_name) == 0);
    assert!(core::mem::offset_of!(MntEnt, directory) == 8);
    assert!(core::mem::offset_of!(MntEnt, filesystem_type) == 16);
    assert!(core::mem::offset_of!(MntEnt, options) == 24);
    assert!(core::mem::offset_of!(MntEnt, frequency) == 32);
    assert!(core::mem::offset_of!(MntEnt, pass_number) == 36);
};

/// Count one NUL-terminated caller C string exactly as musl's `strlen` does.
#[inline]
unsafe fn c_string_length(string: *const c_char) -> usize {
    let mut length = 0usize;
    // SAFETY: the public C boundary requires a readable NUL-terminated option
    // spelling. This walks only to that supplied terminator.
    while core::hint::black_box(unsafe { core::ptr::read(string.wrapping_add(length)) }) != 0 {
        length = length.wrapping_add(1);
    }
    length
}

/// Return whether the first `length` bytes agree, as musl's `strncmp` does.
#[inline]
unsafe fn c_prefix_matches(left: *const c_char, right: *const c_char, length: usize) -> bool {
    let mut offset = 0usize;
    while offset < length {
        // SAFETY: `right` is NUL terminated by the C caller. `left` starts at
        // a valid `mnt_opts` token and musl's same `strncmp` reads these bytes.
        let left_byte =
            core::hint::black_box(unsafe { core::ptr::read(left.wrapping_add(offset)) });
        let right_byte =
            core::hint::black_box(unsafe { core::ptr::read(right.wrapping_add(offset)) });
        if left_byte != right_byte {
            return false;
        }
        // `strncmp` stops once equal NUL bytes end both strings instead of
        // probing later caller storage. For a stable C string this can occur
        // only at the final byte, but retaining the source rule keeps this
        // local byte walk exact even at the caller boundary.
        if left_byte == 0 {
            return true;
        }
        offset = offset.wrapping_add(1);
    }
    true
}

/// Find the first comma at or after `string`, preserving musl's `strchr` scan.
#[inline]
unsafe fn c_comma(string: *mut c_char) -> *mut c_char {
    let mut cursor = string;
    loop {
        // SAFETY: `cursor` remains inside the caller's NUL-terminated options
        // string until this loop returns its comma or terminal null result.
        let byte = core::hint::black_box(unsafe { core::ptr::read(cursor) });
        if byte == b',' as c_char {
            return cursor;
        }
        if byte == 0 {
            return core::ptr::null_mut();
        }
        // SAFETY: `byte` was neither the NUL terminator nor an out-of-range
        // position, so advancing one byte remains in the caller record.
        cursor = cursor.wrapping_add(1);
    }
}

/// Find one whole mount-option spelling in caller-owned `mnt_opts` bytes.
///
/// # Safety
///
/// `entry` must point to a readable C `struct mntent` whose `mnt_opts` field
/// names a readable NUL-terminated byte string. `option` must point to another
/// readable NUL-terminated byte string. The returned pointer, when non-null,
/// aliases the caller's mutable `mnt_opts` storage exactly as musl's C API
/// specifies. Null, dangling, or unterminated input is outside this C ABI's
/// contract and is deliberately not converted into an errno result.
#[no_mangle]
pub unsafe extern "C" fn hasmntopt(entry: *const MntEnt, option: *const c_char) -> *mut c_char {
    // SAFETY: the documented C caller contract makes `option` readable through
    // its NUL terminator, exactly as musl's `strlen(opt)` requires.
    let option_length = unsafe { c_string_length(option) };
    // SAFETY: the documented C caller contract makes `entry` readable and its
    // options field a valid NUL-terminated string pointer, like musl's direct
    // `char *p = mnt->mnt_opts` initialization.
    // `addr_of!` obtains this field address without materializing an
    // intermediate reference or selecting Rust's debug null/alignment panic
    // path. The C ABI still requires the entry record to be valid and aligned.
    let options_field = core::ptr::addr_of!((*entry).options);
    let mut cursor = unsafe { core::ptr::read(options_field) };

    loop {
        // SAFETY: `cursor` begins at mnt_opts or immediately after one of its
        // commas, and `option` is valid for the same source-level comparison.
        let prefix_matches = unsafe {
            c_prefix_matches(cursor.cast_const(), option, option_length)
        };
        // Musl's `&&` evaluates the `p[l]` suffix only after `strncmp` has
        // succeeded. Keeping that order matters when a short final token ends
        // at a caller page boundary: a miss must not probe beyond its NUL.
        if prefix_matches {
            // SAFETY: a successful bounded prefix comparison means this is
            // musl's exact `p[l]` suffix byte. The caller contract gives the
            // options string enough readable bytes for that C expression.
            let suffix = core::hint::black_box(unsafe {
                core::ptr::read(cursor.wrapping_add(option_length))
            });
            if suffix == 0
                || suffix == b',' as c_char
                || suffix == b'=' as c_char
            {
                return cursor;
            }
        }

        // SAFETY: search the current NUL-terminated suffix for musl's next
        // comma. No input byte is mutated or copied by this artifact.
        cursor = unsafe { c_comma(cursor) };
        if cursor.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: a found comma is followed by a byte in the same
        // NUL-terminated caller string, possibly its terminal NUL.
        cursor = cursor.wrapping_add(1);
    }
}
