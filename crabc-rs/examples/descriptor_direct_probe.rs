//! Link-free no-std proof for the native descriptor operations.

#![no_std]

use crabc_rs::{fs, io, pipe};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_descriptor_direct_probe() -> i32 {
    let file = match fs::memfd_create(
        &b"crabc-native-descriptor-probe"[..],
        fs::MemfdFlags::CLOEXEC,
    ) {
        Ok(file) => file,
        Err(error) => return -error.raw(),
    };
    if io::write(&file, b"splice").ok() != Some(6) {
        return 1;
    }
    if fs::seek(&file, fs::SeekFrom::Start(0)).is_err() {
        return 2;
    }

    let (reader, writer) = match pipe::pipe() {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    if pipe::splice(
        &file,
        None,
        &writer,
        None,
        6,
        pipe::SpliceFlags::empty(),
    )
    .ok()
        != Some(6)
    {
        return 3;
    }
    let mut copied = [0_u8; 6];
    if io::read(&reader, &mut copied).ok() != Some(6) || copied != *b"splice" {
        return 4;
    }

    let source = [pipe::IoSliceRaw::from_slice(b"vmsplice")];
    if unsafe { pipe::vmsplice(&writer, &source, pipe::SpliceFlags::empty()) }.ok() != Some(8) {
        return 5;
    }
    let mut transferred = [0_u8; 8];
    if io::read(&reader, &mut transferred).ok() != Some(8)
        || transferred != *b"vmsplice"
    {
        return 6;
    }

    if fs::lock_from_current(
        &file,
        fs::CurrentLockOperation::LockExclusive,
        fs::CurrentLockRange::ToEnd,
    )
    .is_err()
    {
        return 7;
    }
    if fs::lock_from_current(
        &file,
        fs::CurrentLockOperation::Unlock,
        fs::CurrentLockRange::ToEnd,
    )
    .is_err()
    {
        return 8;
    }
    if file.close().is_err() {
        return 9;
    }
    0
}
