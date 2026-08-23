use std::io::ErrorKind;
use std::net::UdpSocket;

use crabc_rs::net;
use crabc_rs::resolver::{IpAddress, SocketAddress};
use crabc_rs::Errno;

#[test]
fn udp_getpeername_round_trips_connected_ipv4_endpoint() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind isolated IPv4 UDP fixture");
    let port = server.local_addr().expect("read IPv4 fixture address").port();
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv4 UDP socket");
    let expected = SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), port);

    net::connect(&socket, expected).expect("connect native IPv4 UDP socket");
    assert_eq!(net::getpeername(&socket).expect("read native IPv4 peer endpoint"), expected);
}

#[test]
fn udp_getpeername_round_trips_connected_ipv6_endpoint() {
    let server = match UdpSocket::bind("[::1]:0") {
        Ok(server) => server,
        Err(error) if matches!(error.kind(), ErrorKind::AddrNotAvailable | ErrorKind::Unsupported) => {
            eprintln!("skipping IPv6 loopback fixture: {error}");
            return;
        }
        Err(error) => panic!("bind isolated IPv6 UDP fixture: {error}"),
    };
    let port = server.local_addr().expect("read IPv6 fixture address").port();
    let socket = net::socket(
        net::AddressFamily::INET6,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv6 UDP socket");
    let expected = SocketAddress::new(
        IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        port,
    );

    net::connect(&socket, expected).expect("connect native IPv6 UDP socket");
    assert_eq!(net::getpeername(&socket).expect("read native IPv6 peer endpoint"), expected);
}

#[test]
fn getpeername_preserves_not_connected_and_rejects_other_families() {
    let unconnected = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create unconnected native IPv4 UDP socket");
    assert_eq!(net::getpeername(&unconnected), Err(Errno::NOTCONN));

    let (left, right) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::empty(),
        None,
    )
    .expect("create connected Unix socket pair");
    assert_eq!(net::getpeername(&left), Err(Errno::AFNOSUPPORT));
    drop(right);
}
