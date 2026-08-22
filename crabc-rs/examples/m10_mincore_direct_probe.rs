//! Link-free no-std proof for the M10 native `mincore` seam.
//!
//! This source is intentionally left unregistered until the M10 evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use crabc_rs::mm::{mincore, mmap_anonymous, munmap, MapFlags, ProtFlags};

const PAGE_SIZE: usize = 4096;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_mincore_direct_probe() -> i32 {
    let mapping = match unsafe {
        mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE * 2,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE,
        )
    } {
        Ok(mapping) => mapping,
        Err(error) => return -error.raw(),
    };

    let result = (|| {
        unsafe { mapping.cast::<u8>().write(0x5a) };
        let mut residency = [0_u8; 2];
        unsafe { mincore(mapping, PAGE_SIZE * 2, &mut residency)? };
        if residency[0] & 1 == 0 {
            return Err(crabc_rs::Errno::IO);
        }
        Ok(())
    })();
    let unmapped = unsafe { munmap(mapping, PAGE_SIZE * 2) };

    match result {
        Ok(()) => match unmapped {
            Ok(()) => 0,
            Err(error) => -error.raw(),
        },
        Err(error) => -error.raw(),
    }
}
