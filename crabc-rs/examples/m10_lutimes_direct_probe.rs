//! Link-free no-std proof for the native no-follow path timestamp seam.

#![no_std]

use crabc_rs::fs::{self, Timeval};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_lutimes_direct_probe() -> i32 {
    let times = [
        Timeval {
            tv_sec: 31,
            tv_usec: 333_333,
        },
        Timeval {
            tv_sec: 32,
            tv_usec: 444_444,
        },
    ];
    if fs::lutimes(&b"/tmp/m10-lutimes"[..], Some(&times)).is_err() {
        return 1;
    }
    if fs::lutimes(&b"/tmp/m10-lutimes"[..], None).is_err() {
        return 2;
    }
    0
}
