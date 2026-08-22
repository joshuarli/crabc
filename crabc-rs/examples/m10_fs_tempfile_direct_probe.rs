//! Link-free no-std proof for the native anonymous temporary-file seam.
//!
//! A filesystem without Linux `O_TMPFILE` support is an explicit capability
//! result, not a request to fall back to a named temporary file.

#![no_std]

use crabc_rs::fs::{self, Mode, TempFile};
use crabc_rs::io;
use crabc_rs::Errno;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_fs_tempfile_direct_probe() -> i32 {
    let file = match TempFile::open("/tmp", Mode::RUSR | Mode::WUSR) {
        Ok(file) => file,
        Err(Errno::OPNOTSUPP) => return 0,
        Err(error) => return -error.raw(),
    };
    if io::write(&file, b"tmp").ok() != Some(3) {
        return 1;
    }
    if fs::seek(&file, fs::SeekFrom::Start(0)).is_err() {
        return 2;
    }
    let mut content = [0_u8; 3];
    if io::read(&file, &mut content).ok() != Some(3) || content != *b"tmp" {
        return 3;
    }
    0
}
