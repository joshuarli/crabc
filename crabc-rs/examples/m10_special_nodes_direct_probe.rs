//! Unregistered no-std release probe for the M10 special-node syscall seam.
//!
//! The architecture harness compiles this source as a static library and
//! inspects its AArch64 references. It intentionally stays out of the Cargo
//! example target list so this probe cannot become an ordinary hosted binary.

#![no_std]

use core::ffi::CStr;

use crabc_rs::fs::{self, FileType, Mode, CWD, FIFO_DEVICE};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_special_nodes_direct_probe() -> i32 {
    // SAFETY: The byte string is static, non-null, and NUL-terminated.
    let path = unsafe {
        CStr::from_bytes_with_nul_unchecked(b"/tmp/crabc-rs-m10-special-nodes-probe\0")
    };

    // Keep repeated probe runs recoverable while touching only the uniquely
    // named fixture owned by this probe.
    let _ = fs::unlink(path);
    match fs::mknodat(
        CWD,
        path,
        FileType::Fifo,
        Mode::RUSR | Mode::WUSR,
        FIFO_DEVICE,
    ) {
        Ok(()) => match fs::unlink(path) {
            Ok(()) => 0,
            Err(error) => -error.raw(),
        },
        Err(error) => -error.raw(),
    }
}
