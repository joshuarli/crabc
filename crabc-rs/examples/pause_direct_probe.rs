//! Link-free no-std proof for the native signal-only wait seam.
//!
//! Calling the exported function blocks until a signal interrupts it. The
//! implementation is intentionally a direct Linux/AArch64 syscall path: it
//! does not call the C `pause` wrapper or inspect TLS `errno`.

#![no_std]
#![crate_type = "staticlib"]

use crabc_rs::event;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_pause_direct_probe() -> i32 {
    event::pause();
    0
}
