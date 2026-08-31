//! Selected static Linux/x86-64 `ctermid` C ABI.
//!
//! This is a narrow translation of pinned musl 1.2.6 release commit
//! `9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license.
//! Source-function mapping: musl `src/unistd/ctermid.c::ctermid` maps to
//! `ctermid` below. Musl returns `s ? strcpy(s, "/dev/tty") : "/dev/tty"`.
//! The fixed literal permits an equivalent direct byte copy here, so this leaf
//! neither imports nor selects the C string-copy API.
//!
//! `ctermid` is historical C ABI compatibility machinery only. It writes the
//! static `/dev/tty` spelling into a caller-owned buffer, or returns a borrowed
//! pointer to that immutable static spelling when passed null. It does not open
//! `/dev/tty`, inspect a descriptor, perform a syscall, allocate, access errno
//! or TLS, or own terminal/session policy. The `char *` result for the null
//! form follows musl's historical C type; callers must not write through its
//! immutable literal pointer. PTY/session helpers, tty discovery, termios,
//! getpass, temporary-file APIs, generic filesystem behavior, dynamic runtime,
//! CRT, loader, sysroot, family completion, promotion, and public x86 support
//! remain outside this selected-private leaf.

use core::ffi::c_char;

const CTERMID_PATH: [u8; 9] = *b"/dev/tty\0";

/// Return the historical controlling-terminal pathname spelling.
///
/// # Safety
///
/// When `buffer` is non-null, it must designate at least nine writable bytes.
/// Portable C callers supply an `L_ctermid`-sized buffer, as required by the
/// C interface. A null `buffer` returns a borrowed immutable static spelling;
/// callers must not write through that result.
#[no_mangle]
pub unsafe extern "C" fn ctermid(buffer: *mut c_char) -> *mut c_char {
    if buffer.is_null() {
        return CTERMID_PATH.as_ptr() as *mut c_char;
    }

    let destination = buffer.cast::<u8>();
    let mut index = 0;
    while index < CTERMID_PATH.len() {
        // SAFETY: the C caller contract above supplies writable storage for
        // the entire fixed spelling, including its terminating NUL.
        unsafe { destination.add(index).write(CTERMID_PATH[index]) };
        index += 1;
    }
    buffer
}
