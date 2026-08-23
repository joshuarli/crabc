//! Link-free no-std proof for the native wall-clock seam.
//!
//! This source is intentionally left unregistered until the evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use crabc_rs::time::{wall_clock, UnixTime, NANOS_PER_SECOND};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_time_direct_probe() -> i32 {
    let now = match wall_clock() {
        Ok(now) => now,
        Err(error) => return -error.raw(),
    };
    if now < UnixTime::UNIX_EPOCH {
        return 1;
    }
    if now.nanoseconds() >= NANOS_PER_SECOND {
        return 2;
    }
    0
}
