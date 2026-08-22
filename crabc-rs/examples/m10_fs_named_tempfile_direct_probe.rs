//! Link-free no-std proof for the native named temporary-file seam.

#![no_std]

use crabc_rs::fs;
use crabc_rs::io;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_fs_named_tempfile_direct_probe() -> i32 {
    let file = match fs::create_temp_file("/tmp", "crabc-rs-m10-named-") {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    if file.name().len() <= b"crabc-rs-m10-named-".len() {
        return 1;
    }
    if !io::fcntl_getfd(&file)
        .map(|flags| flags.contains(io::FdFlags::CLOEXEC))
        .unwrap_or(false)
    {
        return 2;
    }
    0
}
