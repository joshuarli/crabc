//! Link-free no-std proof for the M10 native targeted resource-limit query.

#![no_std]

use crabc_rs::process::{self, Resource};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_rlimit_for_direct_probe() -> i32 {
    let limit = match process::getrlimit_for(None, Resource::Nofile) {
        Ok(limit) => limit,
        Err(error) => return -error.raw(),
    };
    match (limit.current, limit.maximum) {
        (Some(current), Some(maximum)) if current > maximum => 1,
        (None, Some(_)) => 2,
        _ => 0,
    }
}
