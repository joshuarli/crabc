//! Link-free no-std proof for the native followed path timestamp seam.

#![no_std]

use crabc_rs::fs::{self, Timeval};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_utimes_direct_probe() -> i32 {
    let times = [
        Timeval {
            tv_sec: 11,
            tv_usec: 111_111,
        },
        Timeval {
            tv_sec: 12,
            tv_usec: 222_222,
        },
    ];
    if fs::utimes(&b"/tmp/m10-utimes"[..], Some(&times)).is_err() {
        return 1;
    }
    if fs::utimes(&b"/tmp/m10-utimes"[..], None).is_err() {
        return 2;
    }
    0
}
