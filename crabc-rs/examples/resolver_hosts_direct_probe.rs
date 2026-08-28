//! Link-free no-std probe for the staged x86 resolver and hosts boundary.
//!
//! It checks only caller-provided host data and numeric resolver behavior. It
//! deliberately excludes `/etc/services`, `/etc/protocols`, C resolver state,
//! and network exchange.

#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::net::{AddressFamily, SocketType};
use crabc_rs::netdb::HostDatabase;
use crabc_rs::resolver::{IpAddress, LookupFlags, LookupOptions, Resolver, ResolverConfig};

struct ProbeAllocator;

static NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: [u8; 8 * 1024] = [0; 8 * 1024];

unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = core::ptr::addr_of_mut!(HEAP).cast::<u8>() as usize;
        let current = NEXT.load(Ordering::Relaxed);
        let aligned = (base + current + layout.align() - 1) & !(layout.align() - 1);
        let offset = aligned.saturating_sub(base);
        let Some(end) = offset.checked_add(layout.size()) else {
            return core::ptr::null_mut();
        };
        if end > 8 * 1024
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
pub extern "C" fn crabc_rs_resolver_hosts_direct_probe() -> i32 {
    let hosts = match HostDatabase::from_bytes(
        b"192.0.2.17 canonical.example.test alias.example.test\n",
    ) {
        Ok(value) => value,
        Err(_) => return 1,
    };
    let mut config = ResolverConfig::new();
    config.set_hosts(hosts);
    let result = match Resolver::new(config).lookup(
        Some("alias.example.test"),
        Some("443"),
        LookupOptions {
            family: AddressFamily::INET,
            socket_type: Some(SocketType::STREAM),
            protocol: Some(6),
            flags: LookupFlags::CANONNAME | LookupFlags::NUMERICSERV,
        },
    ) {
        Ok(value) => value,
        Err(_) => return 2,
    };
    if result.canonical_name() != Some("canonical.example.test")
        || result.as_slice().len() != 1
        || result.as_slice()[0].address().ip() != IpAddress::V4([192, 0, 2, 17])
        || result.as_slice()[0].address().port() != 443
    {
        return 3;
    }
    0
}
