//! Link-free no-std proof for the native `creat` seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use core::ffi::CStr;

use crabc_rs::fs::{self, Mode};
use crabc_rs::io;
use crabc_rs::Errno;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_create_direct_probe() -> i32 {
    // SAFETY: The byte string is static, non-null, and NUL-terminated.
    let path =
        unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp/crabc-rs-native-create-probe\0") };
    let _ = fs::unlink(path);
    let result = match fs::create(path, Mode::RUSR | Mode::WUSR) {
        Ok(file) => {
            let result = if io::write(&file, b"seed").ok() != Some(4) {
                1
            } else {
                match io::read(&file, &mut [0_u8; 1]) {
                    Err(error) if error == Errno::BADF => 0,
                    Err(_) => 2,
                    Ok(_) => 3,
                }
            };
            drop(file);
            result
        }
        Err(error) => -error.raw(),
    };
    let _ = fs::unlink(path);
    result
}
