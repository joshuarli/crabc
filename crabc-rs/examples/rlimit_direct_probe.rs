//! Link-free no-std proof for the native process resource-limit query.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::process::{self, Resource};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_rlimit_direct_probe() -> i32 {
    let limit = match process::getrlimit(Resource::Nofile) {
        Ok(limit) => limit,
        Err(error) => return -error.raw(),
    };
    match (limit.current, limit.maximum) {
        (Some(current), Some(maximum)) if current > maximum => 1,
        (None, Some(_)) => 2,
        _ => 0,
    }
}
