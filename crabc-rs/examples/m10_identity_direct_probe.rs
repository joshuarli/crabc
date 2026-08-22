//! Link-free no-std proof for the M10 native UID/GID identity seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::process;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_identity_direct_probe() -> i32 {
    let uid = process::getuid();
    let euid = process::geteuid();
    let gid = process::getgid();
    let egid = process::getegid();
    let user_ids = match process::getresuid() {
        Ok(ids) => ids,
        Err(error) => return -error.raw(),
    };
    let group_ids = match process::getresgid() {
        Ok(ids) => ids,
        Err(error) => return -error.raw(),
    };
    if uid.as_raw() == u32::MAX
        || euid.as_raw() == u32::MAX
        || gid.as_raw() == u32::MAX
        || egid.as_raw() == u32::MAX
        || user_ids.real.as_raw() == u32::MAX
        || user_ids.effective.as_raw() == u32::MAX
        || user_ids.saved.as_raw() == u32::MAX
        || group_ids.real.as_raw() == u32::MAX
        || group_ids.effective.as_raw() == u32::MAX
        || group_ids.saved.as_raw() == u32::MAX
    {
        return 1;
    }
    if user_ids.real != uid
        || user_ids.effective != euid
        || group_ids.real != gid
        || group_ids.effective != egid
    {
        return 2;
    }
    0
}
