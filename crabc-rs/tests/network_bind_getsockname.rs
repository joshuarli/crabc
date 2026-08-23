use std::io::ErrorKind;
use std::net::UdpSocket;

use crabc_rs::net;
use crabc_rs::resolver::{IpAddress, SocketAddress};
use crabc_rs::Errno;

#[test]
fn udp_bind_zero_and_getsockname_round_trip_ipv4() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv4 UDP socket");
    let requested = SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), 0);

    net::bind(&socket, requested).expect("bind native IPv4 UDP socket to port zero");
    let actual = net::getsockname(&socket).expect("read native IPv4 local endpoint");

    assert_eq!(actual.ip(), requested.ip());
    assert_eq!(actual.scope_id(), 0);
    assert_ne!(actual.port(), 0, "Linux must assign an ephemeral IPv4 port");
}

#[test]
fn udp_bind_zero_and_getsockname_round_trip_ipv6() {
    match UdpSocket::bind("[::1]:0") {
        Ok(server) => drop(server),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::AddrNotAvailable | ErrorKind::Unsupported
            ) =>
        {
            eprintln!("skipping IPv6 loopback fixture: {error}");
            return;
        }
        Err(error) => panic!("probe IPv6 loopback availability: {error}"),
    }

    let socket = net::socket(
        net::AddressFamily::INET6,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv6 UDP socket");
    let requested = SocketAddress::new(
        IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        0,
    );

    net::bind(&socket, requested).expect("bind native IPv6 UDP socket to port zero");
    let actual = net::getsockname(&socket).expect("read native IPv6 local endpoint");

    assert_eq!(actual.ip(), requested.ip());
    assert_eq!(actual.scope_id(), 0);
    assert_ne!(actual.port(), 0, "Linux must assign an ephemeral IPv6 port");
}

#[test]
fn getsockname_rejects_unsupported_socket_families() {
    let socket = net::socket(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native Unix datagram socket");

    assert_eq!(net::getsockname(&socket), Err(Errno::AFNOSUPPORT));
}

#[test]
fn bind_rejects_ipv4_scope_instead_of_discarding_it() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::empty(),
        None,
    )
    .expect("create native IPv4 UDP socket");
    let requested = SocketAddress::new_scoped(IpAddress::V4([127, 0, 0, 1]), 0, 7);

    assert_eq!(net::bind(&socket, requested), Err(Errno::INVAL));
}
