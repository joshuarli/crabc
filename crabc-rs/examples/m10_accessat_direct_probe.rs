//! Link-free no-std proof for the native directory-relative access seam.

#![no_std]

use crabc_rs::fs::{self, Access, AtFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_accessat_direct_probe() -> i32 {
    if fs::accessat(fs::CWD, &b"/"[..], Access::EXISTS, AtFlags::empty()).is_err() {
        return 1;
    }
    if fs::accessat(
        fs::CWD,
        &b"/"[..],
        Access::EXISTS,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .is_err()
    {
        return 2;
    }
    0
}
