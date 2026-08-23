//! Link-free no-std proof for the native filename-pattern seam.

#![no_std]

use core::ffi::CStr;

use crabc_rs::pattern::{fnmatch, FnmatchFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

fn cstr(bytes: &'static [u8]) -> &'static CStr {
    // SAFETY: Every probe literal below has one trailing NUL and no interior
    // NUL, so it is a valid borrowed C string for the duration of the call.
    unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
}

#[no_mangle]
pub extern "C" fn crabc_rs_fnmatch_direct_probe() -> i32 {
    if !fnmatch(cstr(b"*.rs\0"), cstr(b"lib.rs\0"), FnmatchFlags::empty()) {
        return 1;
    }
    if fnmatch(cstr(b"*\0"), cstr(b"usr/lib\0"), FnmatchFlags::PATHNAME) {
        return 2;
    }
    if !fnmatch(
        cstr(b"usr\0"),
        cstr(b"usr/local\0"),
        FnmatchFlags::PATHNAME | FnmatchFlags::LEADING_DIR,
    ) {
        return 3;
    }
    if !fnmatch(
        cstr(b"[[:alpha:]]*[[:digit:]]\0"),
        cstr(b"crate7\0"),
        FnmatchFlags::empty(),
    ) {
        return 4;
    }
    if !fnmatch(cstr(b"*.RS\0"), cstr(b"lib.rs\0"), FnmatchFlags::CASEFOLD) {
        return 5;
    }
    0
}
