//! Link-free no-std proof for the native Linux priority query.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::process::{self, PriorityTarget};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_priority_direct_probe() -> i32 {
    let priority = match process::getpriority(PriorityTarget::Process(None)) {
        Ok(priority) => priority,
        Err(error) => return -error.raw(),
    };
    let encoded = match crabc_core::process::getpriority_raw(0, 0) {
        Ok(encoded) => encoded,
        Err(error) => return -error.raw(),
    };

    if !(1..=40).contains(&encoded) {
        return 1;
    }
    if !(-20..=19).contains(&priority.as_raw()) {
        return 2;
    }
    if priority.as_raw() != 20 - encoded {
        return 3;
    }
    0
}
