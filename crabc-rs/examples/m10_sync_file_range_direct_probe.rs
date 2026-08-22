//! Link-free no-std proof for the M10 native `sync_file_range` seam.
//!
//! This source is intentionally left unregistered until the architecture
//! harness adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use crabc_rs::fs::{self, Mode, OFlags};
use crabc_rs::io::{self, SyncFileRangeFlags};
use crabc_rs::{AsFd, Errno};

const PATH: &[u8] = b"/tmp/crabc-rs-m10-sync-file-range-probe";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_sync_file_range_direct_probe() -> i32 {
    let _ = fs::unlink(PATH);
    let file = match fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };

    if io::write(&file, b"sync_file_range").is_err() {
        return 1;
    }
    if let Err(error) = io::sync_file_range(
        file.as_fd(),
        0,
        0,
        SyncFileRangeFlags::WAIT_BEFORE
            | SyncFileRangeFlags::WRITE
            | SyncFileRangeFlags::WAIT_AFTER,
    ) {
        return -error.raw();
    }
    if io::sync_file_range(file.as_fd(), i64::MAX as u64, 1, SyncFileRangeFlags::empty())
        != Err(Errno::INVAL)
    {
        return 2;
    }

    drop(file);
    let _ = fs::unlink(PATH);
    0
}
