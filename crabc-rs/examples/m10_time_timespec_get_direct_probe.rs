//! Link-free no-std proof for the native C11 UTC timespec seam.

#![no_std]

use crabc_rs::time::{timespec_get, NANOS_PER_SECOND};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_time_timespec_get_direct_probe() -> i32 {
    let now = match timespec_get() {
        Ok(now) => now,
        Err(error) => return -error.raw(),
    };
    if now.tv_sec <= 0 {
        return 1;
    }
    if !(0..NANOS_PER_SECOND as i64).contains(&now.tv_nsec) {
        return 2;
    }
    0
}
