//! Link-free no-std proof for the native `readahead` seam.
//!
//! This source is intentionally left unregistered until the architecture
//! harness adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::fs::{self, Mode, OFlags};
use crabc_rs::io;

const PATH: &[u8] = b"/tmp/crabc-rs-native-readahead-probe";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_readahead_direct_probe() -> i32 {
    let _ = fs::unlink(PATH);
    let file = match fs::open(
        PATH,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };

    let status = if io::write(&file, b"readahead").is_err() {
        1
    } else {
        match fs::readahead(&file, 0, 9) {
            Ok(()) => 0,
            Err(error) => -error.raw(),
        }
    };

    drop(file);
    let _ = fs::unlink(PATH);
    status
}
