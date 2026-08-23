//! Link-free assembly probe for the direct syscall boundary.
//!
//! This is a `no_std` static library, not an application. Its one exported
//! function monomorphizes the public `crabc-rs` open/read/write/RAII-close
//! path so the verifier can prove that it contains AArch64 `svc` instructions
//! and no call to the public crabc C ABI or TLS errno accessor.

#![cfg_attr(not(feature = "std"), no_std)]

use core::ffi::CStr;
use core::mem::MaybeUninit;

use crabc_rs::fs::{self, Mode, OFlags, CWD};
use crabc_rs::io;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_direct_io_probe() -> i32 {
    // SAFETY: Both byte strings are static, non-null, and terminated exactly
    // once. They are never exposed as mutable data.
    let sink = unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/null\0") };
    let source = unsafe { CStr::from_bytes_with_nul_unchecked(b"/proc/self/cmdline\0") };

    let sink = match fs::openat(CWD, sink, OFlags::WRONLY, Mode::empty()) {
        Ok(fd) => fd,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = io::write(&sink, b"io") {
        return -error.raw();
    }
    if let Err(error) = io::ioctl_fioclex(&sink) {
        return -error.raw();
    }
    if let Err(error) = io::ioctl_fionclex(&sink) {
        return -error.raw();
    }
    drop(sink);

    let source = match fs::openat(CWD, source, OFlags::RDONLY, Mode::empty()) {
        Ok(fd) => fd,
        Err(error) => return -error.raw(),
    };
    let mut bytes = [MaybeUninit::<u8>::uninit(); 1];
    match io::read(&source, &mut bytes) {
        Ok(_) => 0,
        Err(error) => -error.raw(),
    }
}
