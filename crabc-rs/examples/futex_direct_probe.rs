//! Link-free no-std proof for the direct Linux/AArch64 futex wait/wake seam.

#![no_std]
#![crate_type = "staticlib"]

use core::sync::atomic::AtomicU32;
use crabc_rs::thread::futex::{self, Flags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_futex_direct_probe() -> i32 {
    let word = AtomicU32::new(0);
    if futex::wait(&word, Flags::PRIVATE, 1, None) != Err(crabc_rs::Errno::AGAIN) {
        return 1;
    }
    match futex::wake(&word, Flags::PRIVATE, 1) {
        Ok(0) => 0,
        Ok(_) => 2,
        Err(error) => -error.raw(),
    }
}
