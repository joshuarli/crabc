//! Link-free no-std proof for the direct Linux/AArch64 `statx` seam.

#![no_std]

use core::ffi::CStr;

use crabc_rs::fs::{self, AtFlags, StatxFlags, CWD};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_statx_direct_probe() -> i32 {
    // SAFETY: This static byte string is non-null and NUL-terminated.
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp\0") };
    let metadata = match fs::statx(CWD, path, AtFlags::empty(), StatxFlags::BASIC_STATS) {
        Ok(metadata) => metadata,
        Err(error) => return -error.raw(),
    };
    if metadata.stx_mask & StatxFlags::BASIC_STATS.bits() != StatxFlags::BASIC_STATS.bits() {
        return 1;
    }
    if metadata.stx_mode == 0
        || metadata.stx_atime.tv_nsec >= 1_000_000_000
        || metadata.stx_mtime.tv_nsec >= 1_000_000_000
        || metadata.stx_ctime.tv_nsec >= 1_000_000_000
    {
        return 2;
    }
    0
}
