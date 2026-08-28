//! Link-free no-std proof for the direct Linux `statx` seam.

#![no_std]

use core::ffi::CStr;

use crabc_rs::fs::{self, StatxFlags, CWD};

#[cfg(target_arch = "aarch64")]
use crabc_rs::fs::AtFlags as StatxAtFlags;
#[cfg(target_arch = "x86_64")]
use crabc_rs::fs::StatxAtFlags;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_statx_direct_probe() -> i32 {
    // SAFETY: This static byte string is non-null and NUL-terminated.
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp\0") };
    let metadata = match fs::statx(CWD, path, StatxAtFlags::empty(), StatxFlags::BASIC_STATS) {
        Ok(metadata) => metadata,
        Err(error) => return -error.raw(),
    };
    if metadata.stx_mask & StatxFlags::BASIC_STATS.bits() == 0 {
        return 1;
    }
    if metadata.stx_mask & StatxFlags::MODE.bits() != 0 && metadata.stx_mode == 0 {
        return 2;
    }
    if metadata.stx_mask & StatxFlags::ATIME.bits() != 0 && metadata.stx_atime.tv_nsec >= 1_000_000_000 {
        return 3;
    }
    if metadata.stx_mask & StatxFlags::MTIME.bits() != 0 && metadata.stx_mtime.tv_nsec >= 1_000_000_000 {
        return 4;
    }
    if metadata.stx_mask & StatxFlags::CTIME.bits() != 0 && metadata.stx_ctime.tv_nsec >= 1_000_000_000 {
        return 5;
    }
    0
}
