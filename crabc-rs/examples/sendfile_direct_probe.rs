//! Link-free no-std proof for the native `sendfile` seam.
//!
//! This source is intentionally left unregistered until the evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use crabc_rs::fs::{self, Mode, OFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_sendfile_direct_probe() -> i32 {
    let input = match fs::open(&b"/dev/null"[..], OFlags::RDONLY, Mode::empty()) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    let output = match fs::open(&b"/dev/null"[..], OFlags::WRONLY, Mode::empty()) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    let mut offset = 0_u64;
    match fs::sendfile(&output, &input, Some(&mut offset), 0) {
        Ok(_) => 0,
        Err(error) => -error.raw(),
    }
}
