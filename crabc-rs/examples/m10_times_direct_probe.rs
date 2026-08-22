//! Link-free no-std proof for the M10 native Linux `times(2)` query.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use crabc_rs::process;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_times_direct_probe() -> i32 {
    let raw = match crabc_core::process::times_raw() {
        Ok(observation) => observation,
        Err(error) => return -error.raw(),
    };
    let native = match process::times() {
        Ok(observation) => observation,
        Err(error) => return -error.raw(),
    };

    if raw.process.user_ticks < 0
        || raw.process.system_ticks < 0
        || raw.process.children_user_ticks < 0
        || raw.process.children_system_ticks < 0
    {
        return 1;
    }
    if native.user_time().as_raw() < raw.process.user_ticks
        || native.system_time().as_raw() < raw.process.system_ticks
        || native.children_user_time().as_raw() < raw.process.children_user_ticks
        || native.children_system_time().as_raw() < raw.process.children_system_ticks
    {
        return 2;
    }
    0
}
