//! Link-free no-std proof for the native eventfd counter seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks. The
//! counter record stays a private typed `u64`; the probe never calls the C
//! ABI, reads TLS `errno`, or exposes a raw eventfd buffer.

#![no_std]

use crabc_rs::event;
use crabc_rs::Errno;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_eventfd_direct_probe() -> i32 {
    let counter = match event::eventfd(
        0,
        event::EventfdFlags::CLOEXEC | event::EventfdFlags::NONBLOCK,
    ) {
        Ok(counter) => counter,
        Err(error) => return -error.raw(),
    };

    if event::eventfd_read(&counter) != Err(Errno::AGAIN) {
        return 1;
    }
    if event::eventfd_write(&counter, 5).is_err() || event::eventfd_write(&counter, 7).is_err() {
        return 2;
    }
    if event::eventfd_read(&counter) != Ok(12) {
        return 3;
    }
    if event::eventfd_read(&counter) != Err(Errno::AGAIN) {
        return 4;
    }
    if event::eventfd_write(&counter, u64::MAX) != Err(Errno::INVAL) {
        return 5;
    }
    0
}
