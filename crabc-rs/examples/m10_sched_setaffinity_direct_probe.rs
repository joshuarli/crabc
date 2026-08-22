//! Link-free no-std proof for the M10 native CPU-affinity mutation seam.

#![no_std]

use crabc_rs::thread;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_sched_setaffinity_direct_probe() -> i32 {
    let mask = match thread::sched_getaffinity(None) {
        Ok(mask) => mask,
        Err(error) => return -error.raw(),
    };
    match thread::sched_setaffinity(None, &mask) {
        Ok(()) => 0,
        Err(error) => -error.raw(),
    }
}
