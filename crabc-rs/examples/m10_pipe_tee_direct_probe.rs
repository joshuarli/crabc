//! Link-free no-std proof for the M10 native pipe tee seam.

#![no_std]

use crabc_rs::{io, pipe};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_pipe_tee_direct_probe() -> i32 {
    let (source_reader, source_writer) = match pipe::pipe() {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    let (destination_reader, destination_writer) = match pipe::pipe() {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    if io::write(&source_writer, b"tee").ok() != Some(3) {
        return 1;
    }
    if pipe::tee(
        &source_reader,
        &destination_writer,
        3,
        pipe::SpliceFlags::MOVE
            | pipe::SpliceFlags::NONBLOCK
            | pipe::SpliceFlags::MORE
            | pipe::SpliceFlags::GIFT,
    )
    .ok()
        != Some(3)
    {
        return 2;
    }
    let mut duplicated = [0_u8; 3];
    if io::read(&destination_reader, &mut duplicated).ok() != Some(3)
        || duplicated != *b"tee"
    {
        return 3;
    }
    0
}
