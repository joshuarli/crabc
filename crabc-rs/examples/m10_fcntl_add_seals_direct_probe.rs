//! Link-free no-std proof for the native `F_ADD_SEALS` seam.

#![no_std]

use crabc_rs::fs::{self, MemfdFlags, SealFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_fcntl_add_seals_direct_probe() -> i32 {
    let file = match fs::memfd_create(
        &b"crabc-m10-add-seals-probe"[..],
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };

    let seals = SealFlags::GROW | SealFlags::SHRINK;
    if fs::fcntl_add_seals(&file, seals).is_err() {
        return 1;
    }
    match fs::fcntl_get_seals(&file) {
        Ok(observed) if observed == seals => 0,
        Ok(_) => 2,
        Err(error) => -error.raw(),
    }
}
