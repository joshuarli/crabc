//! Link-free proof for direct, owned conventional account snapshots.
//!
//! The probe loads `/etc/passwd` and `/etc/group` through crabc's descriptor
//! boundary and parses them into owned values. It does not call a C passwd or
//! group function, use an NSS provider, or read a C static result buffer.

#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::users::Database;

struct ProbeAllocator;

static NEXT: AtomicUsize = AtomicUsize::new(0);
static mut HEAP: [u8; 64 * 1024] = [0; 64 * 1024];

unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = core::ptr::addr_of_mut!(HEAP).cast::<u8>() as usize;
        let current = NEXT.load(Ordering::Relaxed);
        let aligned = (base + current + layout.align() - 1) & !(layout.align() - 1);
        let offset = aligned.saturating_sub(base);
        let Some(end) = offset.checked_add(layout.size()) else {
            return core::ptr::null_mut();
        };
        if end > 64 * 1024
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
pub extern "C" fn crabc_rs_m13_users_databases_direct_probe() -> i32 {
    let database = match Database::from_system() {
        Ok(database) => database,
        Err(_) => return 1,
    };
    if database.users().is_empty() || database.groups().is_empty() {
        return 2;
    }
    0
}
