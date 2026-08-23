//! Link-free no-std proof for the native `F_GET_SEALS` seam.

#![no_std]

use crabc_rs::fs::{self, MemfdFlags, SealFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_fcntl_seals_direct_probe() -> i32 {
    let file = match fs::memfd_create(
        &b"crabc-native-seals-probe"[..],
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };

    match fs::fcntl_get_seals(&file) {
        Ok(flags) if flags == SealFlags::empty() => 0,
        Ok(_) => 1,
        Err(error) => -error.raw(),
    }
}
