//! Link-free no-std proof for the native addressed-datagram seam.
//!
//! This source is intentionally unregistered until the architecture harness
//! adds the corresponding static-archive and direct-syscall checks.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::net::{self, IpAddress, SocketAddress};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_network_datagram_direct_probe() -> i32 {
    let receiver = match net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };
    let loopback = SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), 0);
    if let Err(error) = net::bind(&receiver, loopback) {
        return -error.raw();
    }
    let destination = match net::getsockname(&receiver) {
        Ok(address) => address,
        Err(error) => return -error.raw(),
    };
    let sender = match net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(error) => return -error.raw(),
    };

    let payload = *b"native-datagram";
    match net::sendto(&sender, &payload, net::SendFlags::empty(), destination) {
        Ok(length) if length == payload.len() => {}
        Ok(_) => return 1,
        Err(error) => return -error.raw(),
    }

    let mut buffer = [MaybeUninit::<u8>::uninit(); 32];
    let ((initialized, remaining), source_length, source) =
        match net::recvfrom(&receiver, &mut buffer, net::RecvFlags::empty()) {
            Ok(result) => result,
            Err(error) => return -error.raw(),
        };
    if &*initialized != payload.as_slice()
        || source_length != payload.len()
        || !remaining.is_empty()
        || source.ip() != loopback.ip()
    {
        return 2;
    }
    if source.port() == 0 || source.scope_id() != 0 {
        return 3;
    }
    0
}
