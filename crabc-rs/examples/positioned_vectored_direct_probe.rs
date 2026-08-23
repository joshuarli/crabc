//! Link-free no-std proof for native positioned vectored descriptor I/O.
//!
//! This source is intentionally unregistered in the focused slice. A verifier
//! can compile it as a static library and inspect that `preadv`/`pwritev`
//! reach Linux/AArch64 directly without the public C ABI or TLS `errno`.

#![no_std]

use crabc_rs::{fs, io};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_positioned_vectored_direct_probe() -> i32 {
    let file = match fs::open(
        "/tmp/crabc-rs-native-positioned-vectored-static-probe",
        fs::OFlags::RDWR | fs::OFlags::CREATE,
        fs::Mode::RUSR | fs::Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    if let Err(error) = fs::ftruncate(&file, 0) {
        return -error.raw();
    }

    let no_writes: [io::IoSlice<'static>; 0] = [];
    if io::pwritev(&file, &no_writes, 0) != Ok(0) {
        return 1;
    }

    let writes = [io::IoSlice::new(b"ab"), io::IoSlice::new(b"CD")];
    if io::pwritev(&file, &writes, 2) != Ok(4) {
        return 2;
    }
    if fs::tell(&file) != Ok(0) {
        return 3;
    }

    let mut first = [0_u8; 2];
    let mut second = [0xa5_u8; 3];
    let read = {
        let mut reads = [
            io::IoSliceMut::new(&mut first),
            io::IoSliceMut::new(&mut second),
        ];
        match io::preadv(&file, &mut reads, 2) {
            Ok(read) => read,
            Err(error) => return -error.raw(),
        }
    };
    if read != 4 || first != *b"ab" || second[..2] != *b"CD" || second[2] != 0xa5 {
        return 4;
    }
    if fs::tell(&file) != Ok(0) {
        return 5;
    }

    let invalid = match io::pwritev(&file, &[io::IoSlice::new(b"x")], u64::MAX) {
        Ok(_) => return 6,
        Err(error) => error,
    };
    if invalid.raw() != 22 {
        return 6;
    }
    0
}
