//! Link-free no-std proof for the native directory-relative timestamp seam.

#![no_std]

use crabc_rs::fs::{self, Mode, OFlags, Timeval, CWD};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_futimesat_direct_probe() -> i32 {
    let directory = match fs::openat(
        CWD,
        &b"/tmp"[..],
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(error) => return -error.raw(),
    };
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
    if fs::futimesat(&directory, &b"native-futimesat"[..], Some(&times)).is_err() {
        return 1;
    }
    if fs::futimesat(&directory, &b"native-futimesat"[..], None).is_err() {
        return 2;
    }
    0
}
