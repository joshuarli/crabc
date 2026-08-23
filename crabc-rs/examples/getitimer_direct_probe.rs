//! Link-free no-std proof for the native `getitimer` seam.
//!
//! This source is intentionally left unregistered until the evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]
#![crate_type = "staticlib"]

use crabc_rs::time::{getitimer, GetitimerError, IntervalTimerKind};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_getitimer_direct_probe() -> i32 {
    for kind in [
        IntervalTimerKind::Real,
        IntervalTimerKind::Virtual,
        IntervalTimerKind::Profiler,
    ] {
        let setting = match getitimer(kind) {
            Ok(setting) => setting,
            Err(GetitimerError::InvalidKernelValue) => return 1,
            Err(GetitimerError::Kernel(error)) => return -error.raw(),
        };
        if setting.interval().subsec_nanos() % 1_000 != 0 {
            return 2;
        }
        if setting.value().subsec_nanos() % 1_000 != 0 {
            return 3;
        }
    }
    0
}
