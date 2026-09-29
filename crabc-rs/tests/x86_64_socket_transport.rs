#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;

use crabc_rs::{fs, io, net};
use crabc_rs::net::{IpAddress, SocketAddress};

fn loopback_v4(port: u16) -> SocketAddress {
    SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), port)
}

fn loopback_v6(port: u16) -> SocketAddress {
    SocketAddress::new(
        IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        port,
    )
}

fn tcp_loopback_pair() -> (crabc_rs::OwnedFd, crabc_rs::OwnedFd) {
    let listener = net::socket(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    ).expect("create native TCP listener");
    net::bind(&listener, loopback_v4(0)).expect("bind native TCP listener");
    net::listen(&listener, 1).expect("listen on native TCP listener");
    let sender = net::socket(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    ).expect("create native TCP sender");
    net::connect(&sender, net::getsockname(&listener).unwrap())
        .expect("connect native TCP sender");
    let receiver = net::accept(&listener).expect("accept native TCP receiver");
    (sender, receiver)
}

#[test]
fn tcp_trunc_reports_discarded_count_without_initializing_the_receive_buffer() {
    let (sender, receiver) = tcp_loopback_pair();
    net::send(&sender, b"abcdefgh", net::SendFlags::empty()).unwrap();
    let mut storage = [0xa5u8; 4];
    let (initialized, count) = net::recv(
        &receiver,
        &mut storage,
        net::RecvFlags::TRUNC | net::RecvFlags::PEEK,
    ).expect("peek at TCP discard count");
    assert_eq!(count, 4);
    assert_eq!(storage, [0xa5; 4]);
    assert_eq!(initialized, 0, "TCP MSG_TRUNC writes no payload bytes");

    let flags = net::RecvFlags::TRUNC | net::RecvFlags::PEEK;
    let mut uninitialized = [MaybeUninit::<u8>::uninit(); 4];
    let ((prefix, suffix), count) = net::recv(&receiver, &mut uninitialized, flags).unwrap();
    assert!(prefix.is_empty());
    assert_eq!(suffix.len(), 4);
    assert_eq!(count, 4);
    let mut empty = [MaybeUninit::<u8>::uninit(); 0];
    let ((prefix, suffix), count) = net::recv(&receiver, &mut empty, flags).unwrap();
    assert!(prefix.is_empty() && suffix.is_empty());
    assert_eq!(count, 0);
    #[cfg(feature = "alloc")]
    for existing in [0, 1] {
        let mut bytes = Vec::with_capacity(4);
        if existing == 1 { bytes.push(0xa5); }
        assert_eq!(net::recv(
            &receiver, crabc_rs::buffer::spare_capacity(&mut bytes), flags,
        ), Ok((0, 4 - existing)));
        assert_eq!(bytes, vec![0xa5; existing]);
        assert_eq!(bytes.capacity(), 4);
    }
    assert_eq!(net::recvfrom(&receiver, &mut storage, flags), Err(crabc_rs::Errno::INVAL));
    assert_eq!(storage, [0xa5; 4]);
    assert_eq!(net::recv(&receiver, &mut storage, net::RecvFlags::PEEK), Ok((4, 4)));
    assert_eq!(&storage, b"abcd");
    assert_eq!(net::recv(&receiver, &mut storage, net::RecvFlags::TRUNC), Ok((0, 4)));
    assert_eq!(&storage, b"abcd");
    assert_eq!(net::recv(&receiver, &mut storage, net::RecvFlags::empty()), Ok((4, 4)));
    assert_eq!(&storage, b"efgh");
}

#[test]
fn tcp_trunc_recvmsg_preserves_count_with_empty_initialized_segments() {
    let (sender, receiver) = tcp_loopback_pair();
    net::send(&sender, b"abcdefgh", net::SendFlags::empty()).unwrap();
    let mut first = [MaybeUninit::new(0xa5u8); 2];
    let mut second = [MaybeUninit::new(0xa5u8); 2];
    let mut buffers = [
        net::MsgIoSliceMut::new_uninit(&mut first),
        net::MsgIoSliceMut::new_uninit(&mut second),
    ];
    let mut message = net::recvmsg(
        &receiver,
        &mut buffers,
        net::RecvFlags::TRUNC | net::RecvFlags::PEEK,
    ).expect("peek at a vectored TCP discard count");
    assert_eq!(message.bytes(), 4);
    let lengths: Vec<_> = message.initialized_segments().map(|bytes| bytes.len()).collect();
    assert_eq!(lengths, [0, 0]);
}

#[test]
fn tcp_trunc_recvmmsg_keeps_completed_disposition_across_reuse_partial_and_error() {
    let (sender, receiver) = tcp_loopback_pair();
    net::send(&sender, b"abcdefghijklmnopqrst", net::SendFlags::empty()).unwrap();
    let mut first = [MaybeUninit::new(0xa5u8); 4];
    let mut second = [MaybeUninit::new(0xa5u8); 4];
    let mut first_buffers = [net::MsgIoSliceMut::new_uninit(&mut first)];
    let mut second_buffers = [net::MsgIoSliceMut::new_uninit(&mut second)];
    let mut messages = [
        net::MMsgHdr::new_recv(&mut first_buffers),
        net::MMsgHdr::new_recv(&mut second_buffers),
    ];
    assert_eq!(net::recvmmsg(
        &receiver, &mut messages, net::RecvFlags::TRUNC | net::RecvFlags::WAITFORONE, None,
    ), Ok(2));
    for message in &mut messages {
        assert_eq!(message.bytes(), 4);
        // SAFETY: this receive record completed successfully and retains its
        // exclusive destination borrow through the initialized-prefix read.
        assert!(unsafe { message.initialized_segments() }.all(|bytes| bytes.is_empty()));
    }

    assert_eq!(net::recvmmsg(
        &receiver, &mut messages, net::RecvFlags::WAITFORONE, None,
    ), Ok(2));
    // SAFETY: both records completed this ordinary receive; their retained
    // destination borrows make the returned prefixes disjoint and live.
    assert_eq!(unsafe { messages[0].initialized_segments() }.next().unwrap(), b"ijkl");
    assert_eq!(unsafe { messages[1].initialized_segments() }.next().unwrap(), b"mnop");

    assert_eq!(net::recvmmsg(
        &receiver, &mut messages, net::RecvFlags::TRUNC | net::RecvFlags::DONTWAIT, None,
    ), Ok(1));
    // SAFETY: the first record completed a discard receive; the second still
    // owns its untouched initialized output from the prior successful call.
    assert!(unsafe { messages[0].initialized_segments() }.all(|bytes| bytes.is_empty()));
    assert_eq!(unsafe { messages[1].initialized_segments() }.next().unwrap(), b"mnop");

    assert_eq!(net::recvmmsg(
        &receiver, &mut messages, net::RecvFlags::TRUNC | net::RecvFlags::DONTWAIT, None,
    ), Err(crabc_rs::Errno::AGAIN));
    // SAFETY: a failed nonblocking call completed neither record, leaving the
    // prior valid output disposition and exclusive borrows unchanged.
    assert!(unsafe { messages[0].initialized_segments() }.all(|bytes| bytes.is_empty()));
    assert_eq!(unsafe { messages[1].initialized_segments() }.next().unwrap(), b"mnop");
}

fn udp_loopback_pair() -> (crabc_rs::OwnedFd, crabc_rs::OwnedFd) {
    let receiver = net::socket(net::AddressFamily::INET, net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC, None).unwrap();
    net::bind(&receiver, loopback_v4(0)).unwrap();
    let sender = net::socket(net::AddressFamily::INET, net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC, None).unwrap();
    net::connect(&sender, net::getsockname(&receiver).unwrap()).unwrap();
    (sender, receiver)
}

#[test]
fn udp_trunc_preserves_full_datagram_count_and_copied_prefix_in_every_receive_form() {
    let (sender, receiver) = udp_loopback_pair();
    net::send(&sender, b"abcdefgh", net::SendFlags::empty()).unwrap();
    let flags = net::RecvFlags::TRUNC | net::RecvFlags::PEEK;
    let mut storage = [0xa5u8; 4];
    assert_eq!(net::recv(&receiver, &mut storage, flags), Ok((4, 8)));
    assert_eq!(&storage, b"abcd");
    let (initialized, count, source) = net::recvfrom(&receiver, &mut storage, flags).unwrap();
    assert_eq!((initialized, count), (4, 8));
    assert_eq!(source.ip(), IpAddress::V4([127, 0, 0, 1]));
    assert_ne!(source.port(), 0);
    let mut uninitialized = [MaybeUninit::<u8>::uninit(); 4];
    let ((prefix, suffix), count) = net::recv(&receiver, &mut uninitialized, flags).unwrap();
    assert_eq!(prefix, b"abcd");
    assert!(suffix.is_empty());
    assert_eq!(count, 8);
    #[cfg(feature = "alloc")]
    {
        let mut bytes = Vec::with_capacity(4);
        bytes.push(0xa5);
        assert_eq!(net::recv(&receiver, crabc_rs::buffer::spare_capacity(&mut bytes), flags), Ok((3, 8)));
        assert_eq!(&bytes, &[0xa5, b'a', b'b', b'c']);
        assert_eq!(bytes.capacity(), 4);
    }
    let mut first = [MaybeUninit::<u8>::uninit(); 2];
    let mut second = [MaybeUninit::<u8>::uninit(); 2];
    let mut buffers = [net::MsgIoSliceMut::new_uninit(&mut first), net::MsgIoSliceMut::new_uninit(&mut second)];
    let mut message = net::recvmsg(&receiver, &mut buffers, flags).unwrap();
    assert_eq!(message.bytes(), 8);
    assert!(message.flags().contains(net::RecvFlags::TRUNC));
    assert_eq!(message.initialized_segments().collect::<Vec<_>>(), [b"ab", b"cd"]);
    let mut first = [MaybeUninit::<u8>::uninit(); 4];
    let mut second = [MaybeUninit::<u8>::uninit(); 4];
    let mut first_buffers = [net::MsgIoSliceMut::new_uninit(&mut first)];
    let mut second_buffers = [net::MsgIoSliceMut::new_uninit(&mut second)];
    let mut messages = [net::MMsgHdr::new_recv(&mut first_buffers), net::MMsgHdr::new_recv(&mut second_buffers)];
    assert_eq!(net::recvmmsg(&receiver, &mut messages, flags | net::RecvFlags::DONTWAIT, None), Ok(2));
    for message in &mut messages {
        assert_eq!(message.bytes(), 8);
        // SAFETY: each receive completed and retains its exclusive buffer borrow.
        assert_eq!(unsafe { message.initialized_segments() }.next().unwrap(), b"abcd");
    }
    assert_eq!(net::recv(&receiver, &mut storage, net::RecvFlags::TRUNC), Ok((4, 8)));
    assert_eq!(net::recv(&receiver, &mut storage, net::RecvFlags::DONTWAIT), Err(crabc_rs::Errno::AGAIN));
}

#[test]
fn unix_stream_trunc_copies_payload_for_scalar_vectored_and_batched_receives() {
    let (sender, receiver) = net::socketpair(net::AddressFamily::UNIX, net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC, None).unwrap();
    net::send(&sender, b"abcdefgh", net::SendFlags::empty()).unwrap();
    let flags = net::RecvFlags::TRUNC | net::RecvFlags::PEEK;
    let mut storage = [MaybeUninit::<u8>::uninit(); 4];
    let ((prefix, _), count) = net::recv(&receiver, &mut storage, flags).unwrap();
    assert_eq!(prefix, b"abcd");
    assert_eq!(count, 4);
    let mut storage = [MaybeUninit::<u8>::uninit(); 4];
    let mut buffers = [net::MsgIoSliceMut::new_uninit(&mut storage)];
    let mut message = net::recvmsg(&receiver, &mut buffers, flags).unwrap();
    assert_eq!(message.bytes(), 4);
    assert_eq!(message.initialized_segments().next().unwrap(), b"abcd");
    let mut storage = [MaybeUninit::<u8>::uninit(); 4];
    let mut buffers = [net::MsgIoSliceMut::new_uninit(&mut storage)];
    let mut messages = [net::MMsgHdr::new_recv(&mut buffers)];
    assert_eq!(net::recvmmsg(&receiver, &mut messages, flags, None), Ok(1));
    assert_eq!(messages[0].bytes(), 4);
    // SAFETY: the record completed a receive into its exclusively borrowed buffer.
    assert_eq!(unsafe { messages[0].initialized_segments() }.next().unwrap(), b"abcd");
}

#[test]
fn sendmmsg_rejects_receive_records_before_reading_payload() {
    let (sender, _receiver) = udp_loopback_pair();
    // Initialized storage makes the pre-fix wrong-direction acceptance safe
    // to observe without asking the kernel to read uninitialized bytes.
    let mut storage = [MaybeUninit::new(b'a'); 4];
    let mut buffers = [net::MsgIoSliceMut::new_uninit(&mut storage)];
    let mut messages = [net::MMsgHdr::new_recv(&mut buffers)];
    assert_eq!(net::sendmmsg(&sender, &mut messages, net::SendFlags::empty()), Err(crabc_rs::Errno::INVAL));
    assert_eq!(messages[0].bytes(), 0);
}

#[test]
fn recvmmsg_rejects_send_records_before_writing_payload() {
    let (sender, receiver) = udp_loopback_pair();
    net::send(&sender, b"queued", net::SendFlags::empty()).unwrap();
    // No iovecs means the pre-fix acceptance cannot write through immutable
    // payload borrows; the returned successful record still witnesses the bug.
    let buffers = [];
    let mut messages = [net::MMsgHdr::new_send(&buffers)];
    assert_eq!(net::recvmmsg(&receiver, &mut messages, net::RecvFlags::DONTWAIT, None), Err(crabc_rs::Errno::INVAL));
    assert_eq!(messages[0].bytes(), 0);
}

#[test]
fn mixed_message_batches_reject_atomically_without_payload_or_timeout_changes() {
    let (sender, receiver) = udp_loopback_pair();
    let outgoing_buffers = [io::IoSlice::new(b"sent")];
    let mut outgoing = [net::MMsgHdr::new_send(&outgoing_buffers)];
    assert_eq!(net::sendmmsg(&sender, &mut outgoing, net::SendFlags::empty()), Ok(1));
    assert_eq!(outgoing[0].bytes(), 4);
    let mut received = [0u8; 8];
    assert_eq!(net::recv(&receiver, &mut received, net::RecvFlags::DONTWAIT), Ok((4, 4)));
    let mut uninitialized = [MaybeUninit::<u8>::uninit(); 4];
    let mut receive_buffers = [net::MsgIoSliceMut::new_uninit(&mut uninitialized)];
    let mut mixed = [outgoing.into_iter().next().unwrap(), net::MMsgHdr::new_recv(&mut receive_buffers)];
    assert_eq!(net::sendmmsg(&sender, &mut mixed, net::SendFlags::empty()), Err(crabc_rs::Errno::INVAL));
    assert_eq!([mixed[0].bytes(), mixed[1].bytes()], [4, 0]);
    assert_eq!(net::recv(&receiver, &mut received, net::RecvFlags::DONTWAIT), Err(crabc_rs::Errno::AGAIN));

    net::send(&sender, b"old!", net::SendFlags::empty()).unwrap();
    let mut storage = [MaybeUninit::<u8>::uninit(); 4];
    let mut buffers = [net::MsgIoSliceMut::new_uninit(&mut storage)];
    let mut incoming = [net::MMsgHdr::new_recv(&mut buffers)];
    assert_eq!(net::recvmmsg(&receiver, &mut incoming, net::RecvFlags::DONTWAIT, None), Ok(1));
    let immutable_buffers = [io::IoSlice::new(b"immutable")];
    let mut mixed = [incoming.into_iter().next().unwrap(), net::MMsgHdr::new_send(&immutable_buffers)];
    net::send(&sender, b"next", net::SendFlags::empty()).unwrap();
    let mut timeout = fs::Timespec { tv_sec: 1, tv_nsec: 234 };
    assert_eq!(net::recvmmsg(&receiver, &mut mixed, net::RecvFlags::TRUNC | net::RecvFlags::DONTWAIT,
        Some(&mut timeout)), Err(crabc_rs::Errno::INVAL));
    assert_eq!((timeout.tv_sec, timeout.tv_nsec), (1, 234));
    assert_eq!([mixed[0].bytes(), mixed[1].bytes()], [4, 0]);
    // SAFETY: the receive record completed before the rejected batch, which
    // touched neither its prior initialized output nor its exclusive borrow.
    assert_eq!(unsafe { mixed[0].initialized_segments() }.next().unwrap(), b"old!");
    assert_eq!(net::recv(&receiver, &mut received, net::RecvFlags::DONTWAIT), Ok((4, 4)));
    assert_eq!(&received[..4], b"next");
}

#[test]
fn empty_message_batches_preserve_the_queued_datagram() {
    let (sender, receiver) = udp_loopback_pair();
    net::send(&sender, b"queued", net::SendFlags::empty()).unwrap();
    let mut messages = [];
    assert_eq!(net::sendmmsg(&sender, &mut messages, net::SendFlags::empty()), Ok(0));
    assert_eq!(net::recvmmsg(&receiver, &mut messages, net::RecvFlags::TRUNC | net::RecvFlags::DONTWAIT, None), Ok(0));
    let mut storage = [0u8; 8];
    assert_eq!(net::recv(&receiver, &mut storage, net::RecvFlags::DONTWAIT), Ok((6, 6)));
    assert_eq!(&storage[..6], b"queued");
    assert_eq!(net::recv(&receiver, &mut storage, net::RecvFlags::DONTWAIT), Err(crabc_rs::Errno::AGAIN));
}

#[test]
fn socketpair_transports_vectored_bytes_and_shutdown_is_typed() {
    let (sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native Unix stream pair");
    assert!(io::fcntl_getfd(&sender).unwrap().contains(io::FdFlags::CLOEXEC));

    let parts = [io::IoSlice::new(b"socket-"), io::IoSlice::new(b"pair")];
    assert_eq!(net::sendmsg(&sender, &parts, net::SendFlags::empty()).unwrap(), 11);

    let mut received = [0_u8; 11];
    let (initialized, count) = net::recv(&receiver, &mut received, net::RecvFlags::empty())
        .expect("receive native socketpair bytes");
    assert_eq!(initialized, 11);
    assert_eq!(count, 11);
    assert_eq!(&received, b"socket-pair");
    assert!(!net::sockatmark(&receiver).expect("query socketpair urgent-data mark"));

    net::shutdown(&sender, net::Shutdown::Write).expect("shut down sender write direction");
    let mut eof = [0_u8; 1];
    let (initialized, count) = net::recv(&receiver, &mut eof, net::RecvFlags::empty())
        .expect("observe socketpair write shutdown");
    assert_eq!(initialized, 0);
    assert_eq!(count, 0);
}

#[test]
fn socket_creation_flags_are_applied_atomically() {
    let socket = net::socket(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        None,
    )
    .expect("create flagged native Unix socket");
    assert!(io::fcntl_getfd(&socket).unwrap().contains(io::FdFlags::CLOEXEC));
    assert!(fs::fcntl_getfl(&socket).unwrap().contains(fs::OFlags::NONBLOCK));
}

#[test]
fn descriptor_addressed_udp_round_trip_reports_bound_and_source_endpoints() {
    let receiver = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native UDP receiver");
    assert_eq!(net::sockopt::socket_type(&receiver).unwrap(), net::SocketType::DGRAM);
    assert_eq!(net::sockopt::socket_domain(&receiver).unwrap(), net::AddressFamily::INET);
    assert_eq!(
        net::sockopt::socket_protocol(&receiver)
            .unwrap()
            .expect("UDP protocol is concrete after native socket creation")
            .as_raw()
            .get(),
        17,
    );
    let cookie = net::sockopt::socket_cookie(&receiver).expect("read stable UDP cookie");
    assert_ne!(cookie, 0);
    assert_eq!(net::sockopt::socket_cookie(&receiver).unwrap(), cookie);
    net::sockopt::set_socket_broadcast(&receiver, true).expect("enable broadcast option");
    assert!(net::sockopt::socket_broadcast(&receiver).unwrap());
    net::bind(&receiver, loopback_v4(0)).expect("bind native UDP receiver");
    let destination = net::getsockname(&receiver).expect("read native UDP bound endpoint");
    assert_eq!(destination.ip(), IpAddress::V4([127, 0, 0, 1]));
    assert_ne!(destination.port(), 0);

    let sender = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native UDP sender");
    let payload = b"addressed-datagram";
    assert_eq!(
        net::sendto(&sender, payload, net::SendFlags::empty(), destination).unwrap(),
        payload.len()
    );

    let mut storage = [0_u8; 64];
    let (initialized, count, source) =
        net::recvfrom(&receiver, &mut storage, net::RecvFlags::empty()).unwrap();
    assert_eq!(initialized, payload.len());
    assert_eq!(count, payload.len());
    assert_eq!(&storage[..initialized], payload);
    assert_eq!(source.ip(), IpAddress::V4([127, 0, 0, 1]));
    assert_ne!(source.port(), 0);
}

#[test]
fn ipv6_datagram_round_trip_preserves_native_endpoint_encoding() {
    let receiver = match net::socket(
        net::AddressFamily::INET6,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    ) {
        Ok(socket) => socket,
        Err(crabc_rs::Errno::AFNOSUPPORT) => return,
        Err(error) => panic!("create native IPv6 UDP receiver: {error:?}"),
    };
    match net::bind(&receiver, loopback_v6(0)) {
        Ok(()) => {}
        Err(crabc_rs::Errno::ADDRNOTAVAIL) => return,
        Err(error) => panic!("bind native IPv6 UDP receiver: {error:?}"),
    }
    let destination = net::getsockname(&receiver).expect("read native IPv6 UDP endpoint");
    assert_eq!(destination.ip(), loopback_v6(0).ip());
    assert_eq!(destination.scope_id(), 0);
    assert_ne!(destination.port(), 0);

    let sender = net::socket(
        net::AddressFamily::INET6,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv6 UDP sender");
    let payload = b"ipv6-addressed-datagram";
    assert_eq!(
        net::sendto(&sender, payload, net::SendFlags::empty(), destination).unwrap(),
        payload.len()
    );
    let mut storage = [0_u8; 64];
    let (initialized, count, source) =
        net::recvfrom(&receiver, &mut storage, net::RecvFlags::empty()).unwrap();
    assert_eq!(initialized, payload.len());
    assert_eq!(count, payload.len());
    assert_eq!(&storage[..initialized], payload);
    assert_eq!(source.ip(), loopback_v6(0).ip());
    assert_eq!(source.scope_id(), 0);
    assert_ne!(source.port(), 0);
}

#[test]
fn loopback_tcp_connect_accept_and_peer_name_preserve_typed_addresses() {
    let listener = net::socket(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native TCP listener");
    assert!(!net::sockopt::socket_acceptconn(&listener).unwrap());
    net::sockopt::set_socket_oobinline(&listener, true).expect("enable inline urgent data");
    assert!(net::sockopt::socket_oobinline(&listener).unwrap());
    net::bind(&listener, loopback_v4(0)).expect("bind native TCP listener");
    net::listen(&listener, 4).expect("listen on native TCP listener");
    assert!(net::sockopt::socket_acceptconn(&listener).unwrap());
    let local = net::getsockname(&listener).expect("read native TCP listener endpoint");

    let client = net::socket(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native TCP client");
    net::connect(&client, local).expect("connect native loopback TCP client");
    let client_local = net::getsockname(&client).expect("read native TCP client endpoint");
    let (accepted, peer) = net::acceptfrom_with(
        &listener,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
    )
        .expect("accept loopback TCP with typed flags");
    assert!(io::fcntl_getfd(&accepted).unwrap().contains(io::FdFlags::CLOEXEC));
    assert!(fs::fcntl_getfl(&accepted).unwrap().contains(fs::OFlags::NONBLOCK));
    assert_eq!(peer.ip(), IpAddress::V4([127, 0, 0, 1]));
    assert_eq!(peer.port(), client_local.port());
    assert_eq!(net::getpeername(&accepted).unwrap(), peer);

    assert_eq!(
        net::send(&client, b"tcp-transport", net::SendFlags::empty()).unwrap(),
        b"tcp-transport".len()
    );
    let mut payload = [0_u8; 32];
    let (initialized, count) = net::recv(&accepted, &mut payload, net::RecvFlags::empty()).unwrap();
    assert_eq!(initialized, b"tcp-transport".len());
    assert_eq!(&payload[..count], b"tcp-transport");

    let plain_client = net::socket(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create second native TCP client");
    net::connect(&plain_client, local).expect("connect second native loopback TCP client");
    let plain_local = net::getsockname(&plain_client).expect("read second client endpoint");
    let plain_accepted = net::accept(&listener).expect("accept without peer-address output");
    assert_eq!(net::getpeername(&plain_accepted).unwrap(), plain_local);
}

#[test]
fn typed_socket_option_and_batched_messages_round_trip() {
    let (sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native datagram pair");
    assert_eq!(net::socket_reuseaddr(&sender).unwrap(), false);
    net::set_socket_reuseaddr(&sender, true).unwrap();
    assert!(net::socket_reuseaddr(&sender).unwrap());

    let first = [io::IoSlice::new(b"batch-one")];
    let second = [io::IoSlice::new(b"batch-two")];
    let mut messages = [net::MMsgHdr::new_send(&first), net::MMsgHdr::new_send(&second)];
    assert_eq!(net::sendmmsg(&sender, &mut messages, net::SendFlags::empty()).unwrap(), 2);
    assert_eq!(messages[0].bytes(), 9);
    assert_eq!(messages[1].bytes(), 9);

    let mut first_storage = [MaybeUninit::<u8>::uninit(); 16];
    let mut second_storage = [MaybeUninit::<u8>::uninit(); 16];
    let mut first_buffers = [net::MsgIoSliceMut::new_uninit(&mut first_storage)];
    let mut second_buffers = [net::MsgIoSliceMut::new_uninit(&mut second_storage)];
    let mut receives = [
        net::MMsgHdr::new_recv(&mut first_buffers),
        net::MMsgHdr::new_recv(&mut second_buffers),
    ];
    assert_eq!(net::recvmmsg(&receiver, &mut receives, net::RecvFlags::empty(), None).unwrap(), 2);
    assert_eq!(receives[0].bytes(), 9);
    assert_eq!(receives[1].bytes(), 9);
    {
        let first_read = unsafe { receives[0].initialized_segments().next().unwrap() };
        assert_eq!(first_read, b"batch-one");
    }
    {
        let second_read = unsafe { receives[1].initialized_segments().next().unwrap() };
        assert_eq!(second_read, b"batch-two");
    }
}

#[test]
fn socket_values_and_recvmsg_are_native_without_resolver_or_c_abi() {
    assert_eq!(
        net::IpAddress::parse(b"127.0.0.1"),
        Some(IpAddress::V4([127, 0, 0, 1]))
    );
    assert_eq!(net::NetworkU16::from_host(0x1234).to_bytes(), [0x12, 0x34]);
    assert_eq!(net::NetworkU32::from_host(0x1234_5678).to_host(), 0x1234_5678);

    let (sender, receiver) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native Unix stream pair for recvmsg");
    let sent = [io::IoSlice::new(b"recv"), io::IoSlice::new(b"msg")];
    assert_eq!(net::sendmsg(&sender, &sent, net::SendFlags::empty()).unwrap(), 7);

    let mut first = [MaybeUninit::<u8>::uninit(); 4];
    let mut second = [MaybeUninit::<u8>::uninit(); 4];
    let mut buffers = [
        net::MsgIoSliceMut::new_uninit(&mut first),
        net::MsgIoSliceMut::new_uninit(&mut second),
    ];
    let mut received = net::recvmsg(&receiver, &mut buffers, net::RecvFlags::empty())
        .expect("receive native vectored message");
    assert_eq!(received.bytes(), 7);
    assert_eq!(received.flags(), net::RecvFlags::empty());
    let mut segments = received.initialized_segments();
    assert_eq!(segments.next().unwrap(), b"recv");
    assert_eq!(segments.next().unwrap(), b"msg");
    assert_eq!(segments.next(), None);
}
