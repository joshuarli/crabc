//! Link-free no-std proof for the owned POSIX shared-memory descriptor seam.

#![no_std]

use core::ffi::CStr;

use crabc_rs::shm::{self, Mode, OFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_shm_direct_probe() -> i32 {
    let name = unsafe { CStr::from_bytes_with_nul_unchecked(b"/crabc-rs-shm-probe\0") };
    let _ = shm::unlink(name);
    let descriptor = match shm::open(
        name,
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => return -error.raw(),
    };
    drop(descriptor);
    match shm::unlink(name) {
        Ok(()) => 0,
        Err(error) => -error.raw(),
    }
}
