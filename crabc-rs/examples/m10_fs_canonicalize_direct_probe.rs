//! Link-free no-std proof for the native filesystem canonicalization seam.

#![no_std]

use core::ffi::CStr;

use crabc_rs::fs;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_fs_canonicalize_direct_probe() -> i32 {
    // SAFETY: This static byte string is non-null and NUL-terminated.
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp/../tmp\0") };
    let mut output = [0u8; fs::CANONICAL_PATH_MAX];
    let length = match fs::canonicalize_into(path, &mut output) {
        Ok(length) => length,
        Err(error) => return -error.raw(),
    };
    if output[..length] != *b"/tmp" {
        return 1;
    }
    // SAFETY: This static byte string is non-null and NUL-terminated.
    let relative = unsafe { CStr::from_bytes_with_nul_unchecked(b".\0") };
    let length = match fs::canonicalize_into(relative, &mut output) {
        Ok(length) => length,
        Err(error) => return -error.raw(),
    };
    if length == 0 || output[0] != b'/' {
        return 2;
    }
    0
}
