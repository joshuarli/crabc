//! Link-free no-std proof for the owned Linux inotify descriptor seam.

#![no_std]

use crabc_rs::system::inotify::{CreateFlags, Inotify};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_inotify_direct_probe() -> i32 {
    let inotify = match Inotify::new(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK) {
        Ok(inotify) => inotify,
        Err(error) => return -error.raw(),
    };
    drop(inotify);
    0
}
