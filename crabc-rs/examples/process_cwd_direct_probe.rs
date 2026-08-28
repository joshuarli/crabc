//! Link-free no-std proof for the process CWD mutation seam.
//!
//! The registered static-library target lets the architecture harness inspect
//! direct `chdir`/`fchdir` calls without adding another public package API.

#![no_std]

use crabc_rs::fs::{self, Mode, OFlags};
use crabc_rs::process;
use crabc_rs::OwnedFd;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

struct CwdGuard {
    original: OwnedFd,
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = process::fchdir(&self.original);
    }
}

#[no_mangle]
pub extern "C" fn crabc_rs_process_cwd_direct_probe() -> i32 {
    let original = match fs::open(
        b".".as_slice(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(error) => return -error.raw(),
    };
    let guard = CwdGuard { original };

    if let Err(error) = process::chdir("/") {
        return -error.raw();
    }
    if let Err(error) = process::fchdir(&guard.original) {
        return -error.raw();
    }
    0
}
