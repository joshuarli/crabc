//! Link-free no-std proof for the native wall-clock seam.
//!
//! The private native evidence runner builds this static archive after its
//! direct `gettimeofday` ABI and calendar-boundary checks pass.

#![no_std]

use crabc_rs::time::{wall_clock, NANOS_PER_SECOND};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_time_direct_probe() -> i32 {
    let now = match wall_clock() {
        Ok(now) => now,
        Err(error) => return -error.raw(),
    };
    if now.nanoseconds() >= NANOS_PER_SECOND {
        return 1;
    }
    0
}
