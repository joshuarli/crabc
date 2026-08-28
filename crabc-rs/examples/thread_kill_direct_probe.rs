//! Link-free no-std proof for direct same-process thread signal delivery.

#![no_std]

use crabc_rs::{signal, thread};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_thread_kill_direct_probe() -> i32 {
    match signal::kill_thread(thread::gettid(), signal::Signal::USR1) {
        Ok(()) => 0,
        Err(error) => -error.raw(),
    }
}
