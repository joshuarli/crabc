//! Link-free no-std proof for explicit local-calendar conversion.
//!
//! The probe supplies both the UTC instant and immutable POSIX timezone rules;
//! it does not read `TZ`, system zoneinfo, the wall clock, or C timezone state.

#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::time::{CalendarTime, LocalCalendar, UnixTime};
use crabc_rs::timezone::TimeZone;

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
pub extern "C" fn crabc_rs_calendar_local_direct_probe() -> i32 {
    let zone = match TimeZone::from_posix_tz(b"EST5EDT4,M3.2.0/2,M11.1.0/2") {
        Ok(zone) => zone,
        Err(_) => return 1,
    };
    let utc = match CalendarTime::from_ymdhms(2024, 3, 10, 7, 0, 0)
        .and_then(|calendar| calendar.unix_seconds())
        .and_then(|seconds| UnixTime::from_parts(seconds, 0).ok_or(crabc_rs::Errno::RANGE))
    {
        Ok(utc) => utc,
        Err(error) => return -error.raw(),
    };
    let local = match LocalCalendar::from_unix_time(utc, &zone) {
        Ok(local) => local,
        Err(error) => return -error.raw(),
    };
    if (
        local.calendar().year(),
        local.calendar().month(),
        local.calendar().day(),
    ) != (2024, 3, 10)
        || (
            local.calendar().hour(),
            local.calendar().minute(),
            local.calendar().second(),
        ) != (3, 0, 0)
        || local.offset().seconds_east_of_utc() != -14_400
        || !local.is_daylight_saving()
        || local.abbreviation() != b"EDT"
    {
        return 2;
    }
    0
}
