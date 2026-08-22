//! Link-free no-std proof for the M10 native CPU-set observation.

#![no_std]

use crabc_rs::thread;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_sched_getaffinity_direct_probe() -> i32 {
    match thread::sched_getaffinity(None) {
        Ok(mask)
            if !mask.is_empty() && mask.count() <= thread::CpuSet::MAX_CPU as u32 =>
        {
            0
        }
        Ok(_) => 1,
        Err(error) => -error.raw(),
    }
}
