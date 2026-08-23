//! Link-free no-std proof for the native pidfd-open seam.

#![no_std]

use crabc_rs::process::{self, PidfdFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_pidfd_open_direct_probe() -> i32 {
    match process::pidfd_open(process::getpid(), PidfdFlags::empty()) {
        Ok(_) => 0,
        Err(error) => -error.raw(),
    }
}
