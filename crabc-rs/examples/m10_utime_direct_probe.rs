//! Link-free no-std proof for the native whole-second path timestamp seam.

#![no_std]

use crabc_rs::fs::{self, Utimbuf};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_utime_direct_probe() -> i32 {
    let times = Utimbuf {
        actime: 41,
        modtime: 42,
    };
    if fs::utime(&b"/tmp/m10-utime"[..], Some(&times)).is_err() {
        return 1;
    }
    if fs::utime(&b"/tmp/m10-utime"[..], None).is_err() {
        return 2;
    }
    0
}
