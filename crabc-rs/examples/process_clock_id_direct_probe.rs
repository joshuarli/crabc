//! Link-free no-std proof for process CPU clock-ID resolution.

#![no_std]

use crabc_rs::time::{self, DynamicClockId};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_process_clock_id_direct_probe() -> i32 {
    let id = match time::clock_getcpuclockid(None) {
        Ok(id) => id,
        Err(_) => return -1,
    };
    match time::clock_gettime_dynamic(DynamicClockId::Process(id)) {
        Ok(value) if value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec) => {
            (id.as_raw() & 1) as i32
        }
        _ => -1,
    }
}
