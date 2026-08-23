//! Link-free no-std proof for the native Linux kernel-thread identity seam.
//!
//! This source is intentionally left unregistered until the architecture
//! harness adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use crabc_rs::thread;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_thread_identity_direct_probe() -> i32 {
    let first = thread::gettid();
    let second = thread::gettid();

    if first.as_raw_pid() <= 0 {
        return 1;
    }
    if first != second {
        return 2;
    }
    0
}
