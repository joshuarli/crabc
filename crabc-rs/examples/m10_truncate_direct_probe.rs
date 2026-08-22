//! Link-free no-std proof for the M10 native pathname `truncate` seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io;
use crabc_rs::Errno;

const PATH: &[u8] = b"/tmp/crabc-rs-m10-truncate-probe";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_truncate_direct_probe() -> i32 {
    let _ = fs::unlink(PATH);
    let file = match fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };

    if io::write(&file, b"truncate").is_err() {
        return 1;
    }
    if fs::truncate(PATH, 3).is_err() {
        return 2;
    }
    if fs::seek(&file, SeekFrom::End(0)).ok() != Some(3) {
        return 3;
    }
    if fs::truncate(PATH, i64::MAX as u64 + 1) != Err(Errno::INVAL) {
        return 4;
    }
    if fs::seek(&file, SeekFrom::End(0)).ok() != Some(3) {
        return 5;
    }

    drop(file);
    let _ = fs::unlink(PATH);
    0
}
