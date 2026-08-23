use core::mem::MaybeUninit;

use crabc_rs::io;
use crabc_rs::net;
use crabc_rs::Errno;

#[test]
fn sendmsg_and_recvmsg_preserve_vectored_boundaries_and_truncation() {
    let (sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create deterministic Unix datagram socket pair");

    let payload = [io::IoSlice::new(b"net-"), io::IoSlice::new(b"msg")];
    assert_eq!(
        net::sendmsg(&sender, &payload, net::SendFlags::empty())
            .expect("send one vectored message"),
        7,
    );

    let mut first = [MaybeUninit::<u8>::uninit(); 3];
    let mut second = [MaybeUninit::<u8>::uninit(); 2];
    let mut buffers = [
        net::MsgIoSliceMut::new_uninit(&mut first),
        net::MsgIoSliceMut::new_uninit(&mut second),
    ];
    let mut received = net::recvmsg(&receiver, &mut buffers, net::RecvFlags::TRUNC)
        .expect("receive one vectored message");
    assert_eq!(received.bytes(), 7, "MSG_TRUNC keeps the datagram length");
    assert!(received.flags().contains(net::RecvFlags::TRUNC));

    let mut initialized = received.initialized_segments();
    assert_eq!(
        initialized.next().expect("first initialized segment"),
        b"net"
    );
    assert_eq!(
        initialized.next().expect("second initialized segment"),
        b"-m"
    );
    assert!(initialized.next().is_none());
}

#[test]
fn recvmsg_nonblocking_empty_queue_returns_again_without_initializing_storage() {
    let (_sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create deterministic Unix datagram socket pair");

    let mut storage = [0xa5_u8; 4];
    let mut buffers = [net::MsgIoSliceMut::new(&mut storage)];
    assert_eq!(
        net::recvmsg(&receiver, &mut buffers, net::RecvFlags::DONTWAIT,).map(|_| ()),
        Err(Errno::AGAIN),
    );
    assert_eq!(storage, [0xa5_u8; 4]);
}
