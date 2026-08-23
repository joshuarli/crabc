#![no_std]
#![crate_type = "staticlib"]

//! Link-free no-std proof for the allocation-enabled native interface-name
//! enumeration seam.
//!
//! The private fixed allocator exists only to make this static probe runnable;
//! production ownership remains the caller's `alloc` feature contract. The
//! implementation still uses direct Linux NETLINK_ROUTE socket/sendto/
//! recvfrom/close operations and never calls the public C allocator or ABI.

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::net::netdevice;

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
pub extern "C" fn crabc_rs_interface_names_alloc_direct_probe() -> i32 {
    let entries = match netdevice::if_nameindex() {
        Ok(entries) => entries,
        Err(error) => return -error.raw(),
    };
    let saw_loopback = entries
        .iter()
        .any(|entry| entry.as_str() == "lo" && entry.index().get() > 0);
    netdevice::if_freenameindex(entries);
    if saw_loopback {
        0
    } else {
        1
    }
}
