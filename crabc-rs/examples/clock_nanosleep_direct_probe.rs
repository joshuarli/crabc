//! Link-free no-std proof for the native `clock_nanosleep` seam.
//!
//! This source is intentionally left unregistered until the evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use core::time::Duration;

use crabc_rs::time::{
    clock_nanosleep_absolute, clock_nanosleep_relative, ClockId, SleepError, SleepOutcome,
    Timespec,
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_clock_nanosleep_direct_probe() -> i32 {
    match clock_nanosleep_relative(ClockId::Monotonic, Duration::ZERO) {
        Ok(SleepOutcome::Completed) => {}
        Ok(SleepOutcome::Interrupted { .. }) => return 1,
        Err(SleepError::DurationOutOfRange | SleepError::InvalidRequest) => return 2,
        Err(SleepError::InvalidRemaining) => return 3,
        Err(SleepError::Kernel(error)) => return -error.raw(),
    }

    match clock_nanosleep_absolute(
        ClockId::Monotonic,
        Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    ) {
        Ok(()) => 0,
        Err(SleepError::DurationOutOfRange | SleepError::InvalidRequest) => 2,
        Err(SleepError::InvalidRemaining) => 3,
        Err(SleepError::Kernel(error)) => -error.raw(),
    }
}
