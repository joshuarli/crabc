//! Link-free no-std proof for the x86 allocation-backed path-core boundary.
//!
//! This static library instantiates both owned `readlink` entry points with a
//! private bump allocator. It deliberately does not exercise canonicalization,
//! directory streams, temporary-object lifecycles, xattrs, or CWD mutation.

#![no_std]
#![crate_type = "staticlib"]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::CStr;
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::fs;

struct ProbeAllocator;

static NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: [u8; 2 * 1024] = [0; 2 * 1024];

unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = core::ptr::addr_of_mut!(HEAP).cast::<u8>() as usize;
        let current = NEXT.load(Ordering::Relaxed);
        let aligned = (base + current + layout.align() - 1) & !(layout.align() - 1);
        let offset = aligned.saturating_sub(base);
        let Some(end) = offset.checked_add(layout.size()) else {
            return core::ptr::null_mut();
        };
        if end > 2 * 1024
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
pub extern "C" fn crabc_rs_path_core_owned_direct_probe() -> i32 {
    // SAFETY: The path is static, NUL-terminated, and has no interior NUL.
    let missing = unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp/crabc-path-core-missing\0") };
    let directory_relative = fs::readlinkat(fs::CWD, missing, Vec::new());
    let current_directory = fs::readlink(missing, Vec::new());

    match (directory_relative, current_directory) {
        (Err(_), Err(_)) => 0,
        _ => 1,
    }
}
