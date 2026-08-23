//! Link-free no-std proof for the native `mremap` seam.
//!
//! This source is intentionally left unregistered until the evidence
//! harness owns its archive and direct-syscall verification rules.

#![no_std]

use crabc_rs::mm::{mmap_anonymous, mremap, munmap, MapFlags, MremapFlags, ProtFlags};

const PAGE_SIZE: usize = 4096;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_mremap_direct_probe() -> i32 {
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

    unsafe { mapping.cast::<u8>().write(0x5a) };
    let successor = unsafe { mremap(mapping, PAGE_SIZE, PAGE_SIZE * 2, MremapFlags::MAYMOVE) };
    let (successor, status) = match successor {
        Ok(successor) if unsafe { successor.cast::<u8>().read() } == 0x5a => {
            (successor, 0)
        }
        Ok(successor) => (successor, -crabc_rs::Errno::IO.raw()),
        Err(error) => {
            // A failed mremap leaves the original mapping valid.
            let _ = unsafe { munmap(mapping, PAGE_SIZE) };
            return -error.raw();
        }
    };

    let unmapped = unsafe { munmap(successor, PAGE_SIZE * 2) };
    match (status, unmapped) {
        (0, Ok(())) => 0,
        (status, Ok(())) => status,
        (_, Err(error)) => -error.raw(),
    }
}
