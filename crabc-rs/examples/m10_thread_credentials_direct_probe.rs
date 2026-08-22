//! Link-free no-std proof for the M10 calling-thread credential slice.
//!
//! The no-change calls retain Linux's direct setresuid/setresgid syscall
//! words, while the explicit all-ones values are rejected by the typed
//! facade before any authority-changing syscall can run.

#![no_std]

use crabc_rs::thread;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_thread_credentials_direct_probe() -> i32 {
    let uid_no_change = thread::set_thread_res_uid(
        Option::<thread::Uid>::None,
        Option::<thread::Uid>::None,
        Option::<thread::Uid>::None,
    );
    let gid_no_change = thread::set_thread_res_gid(
        Option::<thread::Gid>::None,
        Option::<thread::Gid>::None,
        Option::<thread::Gid>::None,
    );
    let uid_sentinel = thread::set_thread_res_uid(
        Some(thread::Uid::from_raw(u32::MAX)),
        Option::<thread::Uid>::None,
        Option::<thread::Uid>::None,
    );
    let gid_sentinel = thread::set_thread_res_gid(
        Some(thread::Gid::from_raw(u32::MAX)),
        Option::<thread::Gid>::None,
        Option::<thread::Gid>::None,
    );

    // Keep all four paths observable to a static verifier without assuming
    // any caller credentials or attempting a real credential transition.
    let mut status: i32 = 0;
    for result in [uid_no_change, gid_no_change, uid_sentinel, gid_sentinel] {
        if let Err(error) = result {
            status = status.wrapping_add(error.raw());
        }
    }
    status
}
