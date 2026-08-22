//! Link-free no-std proof for the M10 native memory-locking seam.
//!
//! This source is intentionally left unregistered until the M10 evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use crabc_rs::mm::{mlock, mlock_with, mmap_anonymous, munlock, munmap, MapFlags, MlockFlags, ProtFlags};

const PAGE_SIZE: usize = 4096;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_mlock_direct_probe() -> i32 {
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

    let result: crabc_rs::Result<()> = (|| {
        unsafe { mlock(mapping, PAGE_SIZE)? };
        unsafe { mlock_with(mapping, PAGE_SIZE, MlockFlags::ONFAULT)? };
        Ok(())
    })();
    let unlocked = unsafe { munlock(mapping, PAGE_SIZE) };
    let unmapped = unsafe { munmap(mapping, PAGE_SIZE) };

    match result {
        Ok(()) => match unlocked {
            Ok(()) => match unmapped {
                Ok(()) => 0,
                Err(error) => -error.raw(),
            },
            Err(error) => -error.raw(),
        },
        Err(error) => -error.raw(),
    }
}
