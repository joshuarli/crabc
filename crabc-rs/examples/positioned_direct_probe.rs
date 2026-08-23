//! Link-free proof for the native positioned descriptor-I/O seam.
//!
//! The probe is intentionally no-std when built without default features. It
//! reaches Linux/AArch64 `pread64` and `pwrite64` through `crabc-core`, with
//! no public C ABI or TLS-`errno` hop.

#![cfg_attr(not(feature = "std"), no_std)]

use crabc_rs::{fs, io};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_positioned_direct_probe() -> i32 {
    let file = match fs::open(
        "/tmp/crabc-rs-native-positioned-static-probe",
        fs::OFlags::RDWR | fs::OFlags::CREATE,
        fs::Mode::RUSR | fs::Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = fs::ftruncate(&file, 0) {
        return -error.raw();
    }
    if let Err(error) = io::pwrite(&file, b"positioned", 3) {
        return -error.raw();
    }
    let mut bytes = [0_u8; 6];
    if let Err(error) = io::pread(&file, &mut bytes, 3) {
        return -error.raw();
    }
    if bytes != *b"itione" {
        return -1;
    }
    0
}
