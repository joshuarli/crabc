//! Link-free no-std proof for the M10 native `access()` seam.
//!
//! This source remains deliberately unregistered: the focused architecture
//! harness can compile it as a static library and inspect its direct syscall
//! without changing the package's public example target list.

#![no_std]

use core::ffi::CStr;

use crabc_rs::fs::{self, Access};
use crabc_rs::Errno;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_access_direct_probe() -> i32 {
    // SAFETY: Both byte strings are static, non-null, and NUL-terminated.
    let current_directory = unsafe { CStr::from_bytes_with_nul_unchecked(b"/\0") };
    let missing = unsafe {
        CStr::from_bytes_with_nul_unchecked(b"/crabc-rs-m10-access-no-such-entry\0")
    };

    if let Err(error) = fs::access(current_directory, Access::EXISTS) {
        return -error.raw();
    }
    match fs::access(missing, Access::EXISTS) {
        Err(error) if error == Errno::NOENT => 0,
        Ok(()) => 1,
        Err(error) => -error.raw(),
    }
}
