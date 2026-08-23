//! Link-free no-std proof for the native scheduler-interval observation.

#![no_std]

use crabc_rs::thread;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_sched_rr_interval_direct_probe() -> i32 {
    match thread::sched_rr_get_interval(None) {
        Ok(interval) if !interval.is_zero() => 0,
        Ok(_) => 1,
        Err(error) => -error.raw(),
    }
}
