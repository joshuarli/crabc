//! Link-free no-std proof for batched message and urgent-mark operations.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::fs::Timespec;
use crabc_rs::{io, net};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_mmsg_direct_probe() -> i32 {
    let (sender, receiver) = match net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(pair) => pair,
        Err(error) => return -error.raw(),
    };
    let first = [io::IoSlice::new(b"native-")];
    let second = [io::IoSlice::new(b"probe")];
    let mut outgoing = [
        net::MMsgHdr::new_send(&first),
        net::MMsgHdr::new_send(&second),
    ];
    if net::sendmmsg(&sender, &mut outgoing, net::SendFlags::empty()) != Ok(2) {
        return 1;
    }

    let mut first_storage = [MaybeUninit::<u8>::uninit(); 4];
    let mut second_storage = [MaybeUninit::<u8>::uninit(); 5];
    let mut first_buffers = [net::MsgIoSliceMut::new_uninit(&mut first_storage)];
    let mut second_buffers = [net::MsgIoSliceMut::new_uninit(&mut second_storage)];
    let mut incoming = [
        net::MMsgHdr::new_recv(&mut first_buffers),
        net::MMsgHdr::new_recv(&mut second_buffers),
    ];
    let mut timeout = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    if net::recvmmsg(
        &receiver,
        &mut incoming,
        net::RecvFlags::empty(),
        Some(&mut timeout),
    ) != Ok(2)
    {
        return 2;
    }
    if incoming[0].bytes() != 4 || incoming[1].bytes() != 5 {
        return 3;
    }
    let mut first_read = unsafe { incoming[0].initialized_segments() };
    match first_read.next() {
        Some(bytes) if bytes == b"native-" => {}
        _ => return 4,
    }
    let mut second_read = unsafe { incoming[1].initialized_segments() };
    match second_read.next() {
        Some(bytes) if bytes == b"probe" => {}
        _ => return 5,
    }

    // The fixed ioctl is part of this direct proof. A datagram socket does
    // not promise an urgent mark, so only require that the call remain a
    // direct, typed operation and accept its kernel result.
    let _ = net::sockatmark(&receiver);
    0
}
