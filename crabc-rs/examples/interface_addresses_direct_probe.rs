#![no_std]
#![crate_type = "staticlib"]

//! Link-free no-std proof for the alloc-gated native interface-address seam.
//!
//! A private fixed allocator makes the static probe runnable in the Docker
//! harness. The implementation itself owns its result with Rust `Vec`s and
//! uses direct NETLINK_ROUTE socket/sendto/recvfrom/close operations only.

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::net::netdevice;

struct ProbeAllocator;

static NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: [u8; 32 * 1024] = [0; 32 * 1024];

unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = core::ptr::addr_of_mut!(HEAP).cast::<u8>() as usize;
        let current = NEXT.load(Ordering::Relaxed);
        let aligned = (base + current + layout.align() - 1) & !(layout.align() - 1);
        let offset = aligned.saturating_sub(base);
        let Some(end) = offset.checked_add(layout.size()) else {
            return core::ptr::null_mut();
        };
        if end > 32 * 1024
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
pub extern "C" fn crabc_rs_interface_addresses_direct_probe() -> i32 {
    let snapshot = match netdevice::InterfaceAddresses::new() {
        Ok(snapshot) => snapshot,
        Err(error) => return -error.raw(),
    };
    let saw_loopback_link = snapshot.entries().iter().any(|entry| match entry {
        netdevice::InterfaceAddress::Link(link) => link.name().as_bytes() == b"lo",
        _ => false,
    });
    let saw_loopback_ip = snapshot.entries().iter().any(|entry| match entry {
        netdevice::InterfaceAddress::Ip(address) => {
            address.name().as_bytes() == b"lo"
                && matches!(
                    address.address().address(),
                    crabc_rs::net::IpAddress::V4([127, 0, 0, 1])
                )
        }
        _ => false,
    });
    if saw_loopback_link && saw_loopback_ip {
        0
    } else {
        1
    }
}
