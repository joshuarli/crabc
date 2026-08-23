//! Link-free no-std proof for the native process CPU-time observation.

#![no_std]

use crabc_rs::time::process_cpu_time;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_process_cpu_time_direct_probe() -> i32 {
    let value = process_cpu_time();
    if value.subsec_nanos() < 1_000_000_000 {
        (value.as_secs() & 1) as i32
    } else {
        1
    }
}
