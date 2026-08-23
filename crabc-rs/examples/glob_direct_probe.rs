//! Link-free no-std proof for the allocation-enabled native glob boundary.
//!
//! The probe supplies an explicit `/tmp` directory descriptor and asks for a
//! deliberately absent pattern. It does not call C `glob`, `globfree`, or a
//! process-global current-directory policy.

#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs;
use crabc_rs::pattern::glob_at;

struct ProbeAllocator;

static NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: [u8; 16 * 1024] = [0; 16 * 1024];

unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = core::ptr::addr_of_mut!(HEAP).cast::<u8>() as usize;
        let current = NEXT.load(Ordering::Relaxed);
        let aligned = (base + current + layout.align() - 1) & !(layout.align() - 1);
        let offset = aligned.saturating_sub(base);
        let Some(end) = offset.checked_add(layout.size()) else {
            return core::ptr::null_mut();
        };
        if end > 16 * 1024
            || NEXT
                .compare_exchange(current, end, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return core::ptr::null_mut();
        }
        aligned as *mut u8
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_glob_direct_probe() -> i32 {
    let directory = match fs::open(
        "/tmp",
        fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(error) => return -error.raw(),
    };
    match glob_at(&directory, b"crabc-rs-compat-glob-probe-absent-*") {
        Ok(matches) if matches.is_empty() => 0,
        Ok(_) => 1,
        Err(error) => -error.raw(),
    }
}
