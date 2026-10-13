//! Link-free no-std proof for the native `madvise` seam.

#![no_std]

use crabc_rs::mm::{madvise, mmap_anonymous, munmap, Advice, MapFlags, ProtFlags};

const PAGE_SIZE: usize = 4096;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_madvise_direct_probe() -> i32 {
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

    let advised = unsafe { madvise(mapping, PAGE_SIZE, Advice::Normal) };
    let unmapped = unsafe { munmap(mapping, PAGE_SIZE) };
    match advised {
        Ok(()) => match unmapped {
            Ok(()) => 0,
            Err(error) => -error.raw(),
        },
        Err(error) => -error.raw(),
    }
}
