//! Link-free no-std proof for the native temporary-directory creation seam.

#![no_std]

use crabc_rs::fs;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_fs_tempdir_direct_probe() -> i32 {
    let mut output = [0u8; 256];
    let length = match fs::create_temp_dir_into("/tmp", "crabc-rs-native-", &mut output) {
        Ok(length) => length,
        Err(error) => return -error.raw(),
    };
    if length <= b"/tmp/crabc-rs-native-".len()
        || output[..length].starts_with(b"/tmp/crabc-rs-native-") == false
    {
        return 1;
    }
    // SAFETY: The output is the exact NUL-free pathname returned by the
    // direct mkdirat operation and remains valid for this call.
    if fs::rmdir(&output[..length]).is_err() {
        return 2;
    }
    0
}
