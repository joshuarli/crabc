//! Link-free no-std proof for the native `syncfs` seam.

#![no_std]

use crabc_rs::fs::{self, Mode, OFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_syncfs_direct_probe() -> i32 {
    let file = match fs::open(&b"/dev/null"[..], OFlags::RDONLY, Mode::empty()) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    match fs::syncfs(&file) {
        Ok(()) => 0,
        Err(error) => -error.raw(),
    }
}
