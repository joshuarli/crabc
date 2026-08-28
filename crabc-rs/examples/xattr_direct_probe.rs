//! Link-free no-std proof for the complete staged x86 xattr facade.
//!
//! The canonical x86 runner builds this static library but does not execute
//! its entry point. Path calls use a missing file; descriptor calls use an
//! intentionally invalid xattr namespace so an executed probe does not mutate
//! a valid Linux xattr namespace.

#![no_std]
#![crate_type = "staticlib"]

use core::ffi::CStr;

use crabc_rs::{fs, BorrowedFd};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

/// Instantiates every staged xattr operation against a caller-provided descriptor.
///
/// # Safety
///
/// `fd` must be a valid, open Linux file descriptor whose owner keeps it open
/// and does not close it through another alias for this function's duration.
#[no_mangle]
pub unsafe extern "C" fn crabc_rs_xattr_direct_probe(fd: i32) -> i32 {
    // SAFETY: The caller contract keeps this borrowed descriptor valid for all
    // immediate facade calls below.
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    // SAFETY: Both literals are static, NUL-terminated C strings without an
    // interior NUL before their terminator.
    let missing = unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp/crabc-xattr-missing\0") };
    let invalid_name = unsafe { CStr::from_bytes_with_nul_unchecked(b"crabc-invalid\0") };
    let mut value = [0_u8; 16];
    let mut list = [0_u8; 64];

    let _ = fs::getxattr(missing, invalid_name, &mut value);
    let _ = fs::lgetxattr(missing, invalid_name, &mut value);
    let _ = fs::fgetxattr(fd, invalid_name, &mut value);
    let _ = fs::setxattr(missing, invalid_name, b"x", fs::XattrFlags::empty());
    let _ = fs::lsetxattr(missing, invalid_name, b"x", fs::XattrFlags::empty());
    let _ = fs::fsetxattr(fd, invalid_name, b"x", fs::XattrFlags::empty());
    let _ = fs::listxattr(missing, &mut list);
    let _ = fs::llistxattr(missing, &mut list);
    let _ = fs::flistxattr(fd, &mut list);
    let _ = fs::removexattr(missing, invalid_name);
    let _ = fs::lremovexattr(missing, invalid_name);
    let _ = fs::fremovexattr(fd, invalid_name);
    0
}
