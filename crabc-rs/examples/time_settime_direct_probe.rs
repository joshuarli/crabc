//! Link-free no-std proof for the direct Linux clock-settime seam.

#![no_std]

use crabc_rs::time::{self, ClockId, Timespec};
use crabc_rs::Errno;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_time_settime_direct_probe() -> i32 {
    let error = match time::clock_settime(
        ClockId::Monotonic,
        Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    ) {
        Ok(()) => return 1,
        Err(error) => error,
    };

    if matches!(error, Errno::INVAL | Errno::PERM) {
        0
    } else {
        -error.raw()
    }
}
