//! Link-free no-std proof for the direct x86 mount error seam.
//!
//! The probe passes checked non-null byte strings and null data through the
//! Rust boundary. It does not need mount authority and makes no successful
//! mount-namespace mutation claim.

#![no_std]

use core::ffi::CStr;

use crabc_rs::mount;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_mount_direct_probe() -> i32 {
    let _ = mount::mount(
        "none",
        "/crabc-rs-x86-mount-direct-probe-missing",
        "tmpfs",
        mount::MountFlags::empty(),
        None::<&CStr>,
    );
    let _ = mount::unmount(
        "/crabc-rs-x86-mount-direct-probe-missing",
        mount::UnmountFlags::empty(),
    );
    0
}
