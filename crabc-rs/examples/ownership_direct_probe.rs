//! Link-free no-std proof for the direct file-ownership slice.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use core::ffi::CStr;

use crabc_rs::fs::{self, ChownFlags};
use crabc_rs::process;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_ownership_direct_probe() -> i32 {
    // SAFETY: This static byte string is non-null and NUL-terminated.
    let missing = unsafe {
        CStr::from_bytes_with_nul_unchecked(b"/crabc-rs-native-ownership-no-such-entry\0")
    };
    let owner = process::geteuid();
    let group = process::getegid();

    // The missing path keeps this probe unprivileged and side-effect free;
    // each call still crosses the direct AArch64 fchown/fchownat syscall seam.
    let chown = fs::chown(missing, Some(owner), Some(group));
    let lchown = fs::lchown(missing, Some(owner), Some(group));
    let chownat = fs::chownat(
        fs::CWD,
        missing,
        None,
        None,
        ChownFlags::empty(),
    );
    let fchown = fs::fchown(fs::CWD, None, None);

    // Keep all four calls observable to a static verifier without depending
    // on a particular host's privilege policy for the missing pathname or
    // reserved descriptor token.
    let mut status: i32 = 0;
    for result in [chown, lchown, chownat, fchown] {
        if let Err(error) = result {
            status = status.wrapping_add(error.raw());
        }
    }
    status
}
