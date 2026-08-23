//! Link-free assembly probe for the direct filesystem boundary.
//!
//! This no-std static library monomorphizes representative filesystem
//! operations. The verifier checks its archive for direct Linux/AArch64
//! syscalls and rejects public C ABI or TLS `errno` entry points.

#![cfg_attr(not(feature = "std"), no_std)]

use core::ffi::CStr;
use core::mem::MaybeUninit;

use crabc_rs::fs::{
    self, AtFlags, FlockOperation, Mode, OFlags, RawDir, ResolveFlags, XattrFlags, CWD,
};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_filesystem_probe() -> i32 {
    // SAFETY: These byte strings are static, non-null, and NUL-terminated.
    let directory = unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp\0") };
    let attribute = unsafe { CStr::from_bytes_with_nul_unchecked(b"user.crabc-rs-probe\0") };
    let entry = unsafe { CStr::from_bytes_with_nul_unchecked(b".\0") };

    let directory = match fs::openat2(
        CWD,
        directory,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) => return -error.raw(),
    };
    let _ = fs::fstat(&directory);
    let _ = fs::statat(&directory, entry, AtFlags::empty());
    let _ = fs::flock(&directory, FlockOperation::NonBlockingLockShared);
    let _ = fs::flock(&directory, FlockOperation::NonBlockingUnlock);
    let _ = fs::fcntl_lock(&directory, FlockOperation::NonBlockingLockShared);
    let _ = fs::fcntl_lock(&directory, FlockOperation::NonBlockingUnlock);

    let mut records = [MaybeUninit::<u8>::uninit(); 64];
    let mut raw_dir = RawDir::new(&directory, &mut records);
    let _ = raw_dir.next();
    drop(raw_dir);

    let mut xattr = [MaybeUninit::<u8>::uninit(); 1];
    let _ = fs::setxattr(entry, attribute, b"fs", XattrFlags::empty());
    let _ = fs::fgetxattr(&directory, attribute, &mut xattr);
    let _ = fs::fsetxattr(&directory, attribute, b"fs", XattrFlags::empty());
    let _ = fs::fremovexattr(&directory, attribute);
    0
}
