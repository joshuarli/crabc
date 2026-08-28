//! Link-free no-std proof for the closed native mapping ownership seam.

#![no_std]

use crabc_rs::mm::{
    mmap_anonymous, mprotect, munmap, MapFlags, MprotectFlags, ProtFlags,
};

const PAGE_SIZE: usize = 4096;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_mapping_direct_probe() -> i32 {
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

    // SAFETY: This function owns the one writable mapping and retains no
    // reference across the direct protection or unmap transitions.
    unsafe { mapping.cast::<u8>().write(0x5a) };
    let protected = unsafe { mprotect(mapping, PAGE_SIZE, MprotectFlags::READ) };
    let observed = match protected {
        Ok(()) => unsafe { mapping.cast::<u8>().read() },
        Err(error) => {
            let _ = unsafe { munmap(mapping, PAGE_SIZE) };
            return -error.raw();
        }
    };
    let restored = unsafe {
        mprotect(
            mapping,
            PAGE_SIZE,
            MprotectFlags::READ | MprotectFlags::WRITE,
        )
    };
    let unmapped = unsafe { munmap(mapping, PAGE_SIZE) };
    match (observed, restored, unmapped) {
        (0x5a, Ok(()), Ok(())) => 0,
        (_, Err(error), _) | (_, _, Err(error)) => -error.raw(),
        _ => -crabc_rs::Errno::IO.raw(),
    }
}
