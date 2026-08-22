//! Link-free no-std proof for the native filesystem-credential seams.
//!
//! The query forms retain Linux's direct setfsuid/setfsgid syscall words while
//! the typed facade keeps the all-ones query sentinel behind `None`.

#![no_std]

use crabc_rs::process;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_fs_credentials_direct_probe() -> i32 {
    let uid = unsafe { process::set_fs_uid(None) };
    let gid = unsafe { process::set_fs_gid(None) };

    // Keep both direct query paths observable to a static verifier without
    // attempting an authority-changing request in the probe itself.
    let mut status: i32 = 0;
    if let Err(error) = uid {
        status = status.wrapping_add(error.raw());
    }
    if let Err(error) = gid {
        status = status.wrapping_add(error.raw());
    }
    status
}
