//! Link-free no-std proof for the native fcntl status-flags seam.

#![no_std]

use crabc_rs::{fs, pipe};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_fcntl_flags_direct_probe() -> i32 {
    let (reader, _writer) = match pipe::pipe() {
        Ok(descriptors) => descriptors,
        Err(error) => return -error.raw(),
    };
    let initial = match fs::fcntl_getfl(&reader) {
        Ok(flags) => flags,
        Err(error) => return -error.raw(),
    };
    if fs::fcntl_setfl(&reader, initial | fs::OFlags::NONBLOCK).is_err() {
        return 1;
    }
    match fs::fcntl_getfl(&reader) {
        Ok(flags) if flags.contains(fs::OFlags::NONBLOCK) => 0,
        Ok(_) => 2,
        Err(error) => -error.raw(),
    }
}
