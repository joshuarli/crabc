//! Link-free no-std proof for the M10 native `msync` seam.
//!
//! This source is intentionally left unregistered until the M10 evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use crabc_rs::mm::{mmap_anonymous, msync, munmap, MapFlags, MsyncFlags, ProtFlags};

const PAGE_SIZE: usize = 4096;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_msync_direct_probe() -> i32 {
    let mapping = match unsafe {
        mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE,
        )
    } {
        Ok(mapping) => mapping,
        Err(error) => return -error.raw(),
    };

    let synchronized = unsafe { msync(mapping, PAGE_SIZE, MsyncFlags::SYNC) };
    let unmapped = unsafe { munmap(mapping, PAGE_SIZE) };
    match synchronized {
        Ok(()) => match unmapped {
            Ok(()) => 0,
            Err(error) => -error.raw(),
        },
        Err(error) => -error.raw(),
    }
}
