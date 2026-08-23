//! Link-free no-std proof for the native Linux process identity seam.
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
pub extern "C" fn crabc_rs_process_identity_direct_probe() -> i32 {
    let pid = process::getpid();
    let parent = process::getppid();

    if pid.as_raw_pid() <= 0 {
        return 1;
    }
    if let Some(parent) = parent {
        if parent.as_raw_pid() <= 0 {
            return 2;
        }
    }
    0
}
