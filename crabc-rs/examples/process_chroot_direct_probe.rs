//! Link-free no-std proof for the process-root error seam.

#![no_std]

use crabc_rs::process;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_process_chroot_direct_probe() -> i32 {
    match process::chroot(b"/crabc-rs-native-chroot-does-not-exist".as_slice()) {
        Err(error) if error == crabc_rs::Errno::NOENT => 0,
        Err(error) => -error.raw(),
        Ok(()) => -1,
    }
}
