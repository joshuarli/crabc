//! Link-free no-std proof for the native `fadvise` seam.
//!
//! This source is intentionally left unregistered until the evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use crabc_rs::fs::{self, Advice, Mode, OFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_fadvise_direct_probe() -> i32 {
    let file = match fs::open(&b"/dev/null"[..], OFlags::RDONLY, Mode::empty()) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    match fs::fadvise(&file, 0, None, Advice::Normal) {
        Ok(()) => 0,
        Err(error) => -error.raw(),
    }
}
