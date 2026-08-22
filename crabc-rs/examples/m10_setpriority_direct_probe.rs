//! Link-free no-std proof for the M10 native Linux `setpriority` operation.

#![no_std]

use crabc_rs::process::{self, Priority};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_setpriority_direct_probe() -> i32 {
    match process::setpriority_process(None, Priority::MAX) {
        Ok(()) => 0,
        Err(error) => -error.raw(),
    }
}
