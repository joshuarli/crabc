//! Link-free no-std proof for the dynamic clock query seam.

#![no_std]

use crabc_rs::time::{clock_gettime_dynamic, ClockId, DynamicClockId, NANOS_PER_SECOND};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_time_dynamic_direct_probe() -> i32 {
    let now = match clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic)) {
        Ok(now) => now,
        Err(error) => return -error.raw(),
    };
    if now.tv_sec < 0 {
        return 1;
    }
    if !(0..NANOS_PER_SECOND as i64).contains(&now.tv_nsec) {
        return 2;
    }
    0
}
