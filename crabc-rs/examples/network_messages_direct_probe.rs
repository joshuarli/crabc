//! Link-free no-std proof for the native vectored message seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::{io, net};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_messages_direct_probe() -> i32 {
    let (sender, receiver) = match net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };

    let payload = [io::IoSlice::new(b"native-"), io::IoSlice::new(b"probe")];
    match net::sendmsg(&sender, &payload, net::SendFlags::empty()) {
        Ok(length) if length == 9 => {}
        Ok(_) => return 1,
        Err(error) => return -error.raw(),
    }

    let mut first = [MaybeUninit::<u8>::uninit(); 4];
    let mut second = [MaybeUninit::<u8>::uninit(); 5];
    let mut buffers = [
        net::MsgIoSliceMut::new_uninit(&mut first),
        net::MsgIoSliceMut::new_uninit(&mut second),
    ];
    let mut received = match net::recvmsg(&receiver, &mut buffers, net::RecvFlags::empty()) {
        Ok(message) => message,
        Err(error) => return -error.raw(),
    };
    if received.bytes() != 9 {
        return 2;
    }
    let mut initialized = received.initialized_segments();
    let first = match initialized.next() {
        Some(bytes) => bytes,
        None => return 3,
    };
    if first != b"native-" {
        return 3;
    }
    let second = match initialized.next() {
        Some(bytes) => bytes,
        None => return 4,
    };
    if second != b"probe" {
        return 4;
    }
    0
}
