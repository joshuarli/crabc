//! Link-free no-std proof for the M10 native Linux load-average observation.

#![no_std]

use crabc_rs::system;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_load_average_direct_probe() -> i32 {
    let loads = system::load_average();
    if loads.one_minute.is_finite()
        && loads.one_minute >= 0.0
        && loads.five_minutes.is_finite()
        && loads.five_minutes >= 0.0
        && loads.fifteen_minutes.is_finite()
        && loads.fifteen_minutes >= 0.0
    {
        0
    } else {
        1
    }
}
