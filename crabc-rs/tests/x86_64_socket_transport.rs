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
