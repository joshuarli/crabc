use core::mem::MaybeUninit;

use crabc_rs::fs::Timespec;
use crabc_rs::{io, net, Errno};

#[test]
fn sendmmsg_and_recvmmsg_preserve_each_record_and_timeout() {
    let (sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create datagram pair");

    let first_payload = [io::IoSlice::new(b"one")];
    let second_payload = [io::IoSlice::new(b"two-two")];
    let mut outgoing = [
        net::MMsgHdr::new_send(&first_payload),
        net::MMsgHdr::new_send(&second_payload),
    ];
    assert_eq!(
        net::sendmmsg(&sender, &mut outgoing, net::SendFlags::empty())
            .expect("send two datagrams"),
        2,
    );
    assert_eq!(outgoing[0].bytes(), 3);
    assert_eq!(outgoing[1].bytes(), 7);

    let mut first_storage = [MaybeUninit::<u8>::uninit(); 3];
    let mut second_storage = [MaybeUninit::<u8>::uninit(); 7];
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
    assert_eq!(
        net::recvmmsg(
            &receiver,
            &mut incoming,
            net::RecvFlags::empty(),
            Some(&mut timeout),
        )
        .expect("receive two datagrams"),
        2,
    );
    assert_eq!(incoming[0].bytes(), 3);
    assert_eq!(incoming[1].bytes(), 7);

    let mut first = unsafe { incoming[0].initialized_segments() };
    assert_eq!(first.next().expect("first message bytes"), b"one");
    assert!(first.next().is_none());
    let mut second = unsafe { incoming[1].initialized_segments() };
    assert_eq!(second.next().expect("second message bytes"), b"two-two");
    assert!(second.next().is_none());
}

#[test]
fn recvmmsg_keeps_partial_success_and_does_not_read_uninitialized_storage() {
    let (sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create datagram pair");
    let payload = [io::IoSlice::new(b"partial")];
    let mut outgoing = [net::MMsgHdr::new_send(&payload)];
    assert_eq!(net::sendmmsg(&sender, &mut outgoing, net::SendFlags::empty()), Ok(1));

    let mut first_storage = [MaybeUninit::<u8>::uninit(); 7];
    let mut second_storage = [MaybeUninit::<u8>::uninit(); 8];
    let mut first_buffers = [net::MsgIoSliceMut::new_uninit(&mut first_storage)];
    let mut second_buffers = [net::MsgIoSliceMut::new_uninit(&mut second_storage)];
    let mut incoming = [
        net::MMsgHdr::new_recv(&mut first_buffers),
        net::MMsgHdr::new_recv(&mut second_buffers),
    ];
    assert_eq!(
        net::recvmmsg(
            &receiver,
            &mut incoming,
            net::RecvFlags::DONTWAIT,
            None,
        ),
        Ok(1),
    );
    assert_eq!(incoming[0].bytes(), 7);
    assert_eq!(incoming[1].bytes(), 0, "unsent records stay untouched");
    let mut first = unsafe { incoming[0].initialized_segments() };
    assert_eq!(first.next().expect("initialized first message"), b"partial");
    assert!(first.next().is_none());
    let mut second = unsafe { incoming[1].initialized_segments() };
    assert_eq!(second.next().expect("empty second message"), b"");
    assert!(second.next().is_none());
}

#[test]
fn recvmmsg_empty_nonblocking_queue_returns_again() {
    let (_sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create datagram pair");
    let mut storage = [0xa5_u8; 4];
    let mut buffers = [net::MsgIoSliceMut::new(&mut storage)];
    let mut incoming = [net::MMsgHdr::new_recv(&mut buffers)];
    assert_eq!(
        net::recvmmsg(
            &receiver,
            &mut incoming,
            net::RecvFlags::DONTWAIT,
            None,
        ),
        Err(Errno::AGAIN),
    );
    assert_eq!(storage, [0xa5_u8; 4]);
}

#[test]
fn sockatmark_reports_non_socket_errors_directly() {
    let file = std::fs::File::open("Cargo.toml").expect("open regular file");
    assert_eq!(net::sockatmark(&file), Err(Errno::NOTTY));
}
