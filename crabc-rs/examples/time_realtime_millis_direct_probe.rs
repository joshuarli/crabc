//! Link-free no-std proof for the native realtime-millisecond seam.

#![no_std]

use crabc_rs::time::realtime_millis;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_time_realtime_millis_direct_probe() -> i32 {
    let now = match realtime_millis() {
        Ok(now) => now,
        Err(error) => return -error.raw(),
    };
    if now.seconds() <= 0 {
        return 1;
    }
    if now.milliseconds() >= 1_000 {
        return 2;
    }
    0
}
