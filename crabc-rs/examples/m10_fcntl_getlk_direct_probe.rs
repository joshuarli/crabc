//! Link-free no-std proof for the native Linux `fcntl(F_GETLK)` query seam.

#![no_std]

use crabc_rs::{fs, process};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_fcntl_getlk_direct_probe() -> i32 {
    let file = match fs::memfd_create(
        &b"crabc-m10-fcntl-getlk-probe"[..],
        fs::MemfdFlags::CLOEXEC,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    let query = process::Flock::from(process::FlockType::ReadLock);
    match process::fcntl_getlk(&file, &query) {
        Ok(None) => 0,
        Ok(Some(_)) => 1,
        Err(error) => -error.raw(),
    }
}
