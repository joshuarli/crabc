//! Link-free no-std proof for the M10 filesystem-statistics seam.
//!
//! The probe is intentionally kept as a separate source file so the harness
//! can register it with the existing static-library verifier without changing
//! the public Cargo feature surface in this focused slice.

#![no_std]

use core::ffi::CStr;

use crabc_rs::fs::{self, Mode, OFlags, CWD};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_fs_metadata_direct_probe() -> i32 {
    // SAFETY: This static byte string is non-null and NUL-terminated.
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp\0") };
    let by_path = match fs::statfs(path) {
        Ok(stats) => stats,
        Err(error) => return -error.raw(),
    };
    if by_path.f_bsize <= 0 {
        return 1;
    }

    let directory = match fs::openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) => return -error.raw(),
    };
    let by_fd = match fs::fstatfs(&directory) {
        Ok(stats) => stats,
        Err(error) => return -error.raw(),
    };
    if by_path.f_type != by_fd.f_type || by_path.f_fsid != by_fd.f_fsid {
        return 2;
    }
    if fs::statvfs(path).is_err() || fs::fstatvfs(&directory).is_err() {
        return 3;
    }
    0
}
