//! Link-free no-std proof for the native fallocate seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::fs::{self, FallocateFlags, Mode, OFlags, SeekFrom};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_fallocate_direct_probe() -> i32 {
    let path = &b"/tmp/crabc-rs-native-fallocate-probe"[..];
    let _ = fs::unlink(path);
    let file = match fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };

    if fs::fallocate(&file, FallocateFlags::ALLOCATE, 4096, 4096).is_err() {
        return 1;
    }
    if fs::tell(&file).ok() != Some(0) {
        return 2;
    }
    if fs::seek(&file, SeekFrom::End(0)).ok() != Some(8192) {
        return 3;
    }
    if fs::ftruncate(&file, 0).is_err() {
        return 4;
    }
    if fs::posix_fallocate(&file, 4096, 4096).is_err() {
        return 5;
    }
    if fs::tell(&file).ok() != Some(0) {
        return 6;
    }
    if fs::seek(&file, SeekFrom::End(0)).ok() != Some(8192) {
        return 7;
    }
    if fs::fallocate(&file, FallocateFlags::ALLOCATE, i64::MAX as u64, 1)
        .err()
        != Some(crabc_rs::Errno::INVAL)
    {
        return 8;
    }
    if fs::posix_fallocate(&file, i64::MAX as u64, 1).err()
        != Some(crabc_rs::Errno::INVAL)
    {
        return 9;
    }
    0
}
