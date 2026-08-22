//! Link-free no-std proof for the M10 native interrupt-aware sleep seam.
//!
//! This source is intentionally left unregistered until the M10 evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use core::time::Duration;

use crabc_rs::time::{nanosleep, SleepError, SleepOutcome};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_sleep_direct_probe() -> i32 {
    match nanosleep(Duration::ZERO) {
        Ok(SleepOutcome::Completed) => 0,
        Ok(SleepOutcome::Interrupted { .. }) => 1,
        Err(
            SleepError::DurationOutOfRange
            | SleepError::InvalidRequest
            | SleepError::InvalidRemaining,
        ) => 2,
        Err(SleepError::Kernel(error)) => -error.raw(),
    }
}
