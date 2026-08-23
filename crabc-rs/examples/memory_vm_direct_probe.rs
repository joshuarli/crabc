//! Link-free no-std proof for the process-break and VM-policy seam.

#![no_std]

use crabc_rs::mm::{self, MapFlags, MlockAllFlags, PosixAdvice, ProtFlags};
use crabc_rs::process::kernel_brk;

const PAGE_SIZE: usize = 4096;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_memory_vm_direct_probe() -> i32 {
    let current = match unsafe { kernel_brk(core::ptr::null_mut()) } {
        Ok(value) if !value.is_null() => value,
        Ok(_) => return -1,
        Err(error) => return -error.raw(),
    };
    match unsafe { kernel_brk(current) } {
        Ok(value) if value == current => {}
        Ok(_) => return -2,
        Err(error) => return -error.raw(),
    }

    let mapping = match unsafe {
        mm::mmap_anonymous(
            core::ptr::null_mut(),
            PAGE_SIZE,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE,
        )
    } {
        Ok(mapping) => mapping,
        Err(error) => return -error.raw(),
    };

    let advisory = unsafe { mm::posix_madvise(mapping, PAGE_SIZE, PosixAdvice::Normal) };
    let legacy = unsafe { mm::remap_file_pages(mapping, PAGE_SIZE, 0) };
    let unlocked = mm::mlockall(MlockAllFlags::CURRENT).map(|_| mm::munlockall());
    let unmapped = unsafe { mm::munmap(mapping, PAGE_SIZE) };

    if let Err(error) = advisory {
        return -error.raw();
    }
    if !matches!(legacy, Err(crabc_rs::Errno::INVAL)) {
        return -3;
    }
    if let Ok(Err(error)) = unlocked {
        return -error.raw();
    }
    match unmapped {
        Ok(()) => 0,
        Err(error) => -error.raw(),
    }
}
