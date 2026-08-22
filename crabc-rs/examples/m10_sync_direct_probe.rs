//! Link-free no-std proof for the M10 native global `sync` seam.
//!
//! This source is intentionally left unregistered until the M10 evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use crabc_rs::fs;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_sync_direct_probe() -> i32 {
    fs::sync();
    0
}
