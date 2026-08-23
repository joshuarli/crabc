//! Link-free no-std probe for the native resolver/netdb boundary.
//!
//! The probe exercises owned numeric resolution, caller-provided netdb parsing,
//! and direct caller-owned system resolver snapshots. It deliberately does not
//! expose or call the C resolver ABI or perform a network lookup.

#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::netdb::{HostDatabase, ProtocolDatabase, ServiceDatabase};
use crabc_rs::resolver::{IpAddress, LookupOptions, Resolver, ResolverConfig};

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
pub extern "C" fn crabc_rs_resolver_direct_probe() -> i32 {
    let resolver = Resolver::new(ResolverConfig::default());
    if resolver
        .lookup(Some("127.0.0.1"), None, LookupOptions::default())
        .is_err()
    {
        return 1;
    }
    if HostDatabase::from_bytes(b"127.0.0.1 localhost").is_err()
        || ServiceDatabase::from_bytes(b"domain 53/udp").is_err()
        || ProtocolDatabase::from_bytes(b"udp 17").is_err()
    {
        return 2;
    }
    if IpAddress::parse(b"127.0.0.1").is_none() {
        return 3;
    }
    let system = match ResolverConfig::from_system() {
        Ok(config) => config,
        Err(_) => return 4,
    };
    if system.hosts().is_none()
        || system.search_domains().len() > 6
        || system.nameserver_count() > 3
    {
        return 5;
    }
    0
}
