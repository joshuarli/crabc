//! Link-free no-std proof for the M10 native `preadv2`/`pwritev2` seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and syscall checks.

#![no_std]

use crabc_rs::fs::{self, Mode, OFlags, SeekFrom};
use crabc_rs::io::{self, ReadWriteFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_preadv2_direct_probe() -> i32 {
    let path = &b"/tmp/crabc-rs-m10-preadv2-probe"[..];
    let _ = fs::unlink(path);
    let file = match fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    if io::write(&file, b"0123456789").ok() != Some(10) {
        return 1;
    }
    if fs::seek(&file, SeekFrom::Start(2)).ok() != Some(2) {
        return 2;
    }

    let current_writes = [io::IoSlice::new(b"ab"), io::IoSlice::new(b"CD")];
    if io::pwritev2(
        &file,
        &current_writes,
        u64::MAX,
        ReadWriteFlags::empty(),
    )
    .ok()
        != Some(4)
        || fs::tell(&file).ok() != Some(6)
    {
        return 3;
    }

    let high_offset = (1_u64 << 32) + 7;
    let high_writes = [io::IoSlice::new(b"hi"), io::IoSlice::new(b"GH")];
    if io::pwritev2(
        &file,
        &high_writes,
        high_offset,
        ReadWriteFlags::empty(),
    )
    .ok()
        != Some(4)
    {
        return 4;
    }
    let mut first = [0_u8; 2];
    let mut second = [0_u8; 2];
    let mut reads = [io::IoSliceMut::new(&mut first), io::IoSliceMut::new(&mut second)];
    if io::preadv2(
        &file,
        &mut reads,
        high_offset,
        ReadWriteFlags::empty(),
    )
    .ok()
        != Some(4)
        || first != *b"hi"
        || second != *b"GH"
    {
        return 5;
    }
    0
}
