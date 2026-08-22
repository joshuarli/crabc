//! Link-free no-std proof for the native descriptor timestamp seam.

#![no_std]

use crabc_rs::fs::Timeval;
use crabc_rs::{fs, pipe};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_futimes_direct_probe() -> i32 {
    let (reader, _writer) = match pipe::pipe() {
        Ok(descriptors) => descriptors,
        Err(error) => return -error.raw(),
    };
    let times = [
        Timeval {
            tv_sec: 41,
            tv_usec: 123_456,
        },
        Timeval {
            tv_sec: 42,
            tv_usec: 654_321,
        },
    ];
    if fs::futimes(&reader, Some(&times)).is_err() {
        return 1;
    }
    if fs::futimes(&reader, None).is_err() {
        return 2;
    }
    0
}
