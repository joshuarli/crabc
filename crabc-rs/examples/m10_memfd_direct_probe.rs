//! Link-free no-std proof for the M10 native memfd-create seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::fs::{self, MemfdFlags, SeekFrom};
use crabc_rs::io;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_memfd_direct_probe() -> i32 {
    let file = match fs::memfd_create(&b"crabc-m10-probe"[..], MemfdFlags::CLOEXEC) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    if io::write(&file, b"mfd").ok() != Some(3) {
        return 1;
    }
    if fs::seek(&file, SeekFrom::Start(0)).is_err() {
        return 2;
    }
    let mut content = [0_u8; 3];
    if io::read(&file, &mut content).ok() != Some(3) || content != *b"mfd" {
        return 3;
    }
    0
}
