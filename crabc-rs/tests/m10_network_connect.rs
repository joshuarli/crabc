use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::Duration;

use crabc_rs::net;
use crabc_rs::resolver::{IpAddress, SocketAddress};
use crabc_rs::Errno;

#[test]
fn udp_connect_encodes_ipv4_loopback_endpoint() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind isolated IPv4 UDP fixture");
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set IPv4 fixture timeout");
    let port = server.local_addr().expect("read IPv4 fixture address").port();
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv4 UDP socket");
    let endpoint = SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), port);

    net::connect(&socket, endpoint).expect("connect native IPv4 UDP socket");
    assert_eq!(net::send(&socket, b"m10-v4", net::SendFlags::empty()).unwrap(), 6);

    let mut received = [0u8; 32];
    let (length, peer) = server.recv_from(&mut received).expect("receive IPv4 fixture datagram");
    assert_eq!(&received[..length], b"m10-v4");
    assert!(peer.ip().is_ipv4());
}

#[test]
fn udp_connect_encodes_ipv6_loopback_endpoint() {
    let server = match UdpSocket::bind("[::1]:0") {
        Ok(server) => server,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::AddrNotAvailable | ErrorKind::Unsupported
            ) => {
                eprintln!("skipping IPv6 loopback fixture: {error}");
                return;
            }
        Err(error) => panic!("bind isolated IPv6 UDP fixture: {error}"),
    };
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set IPv6 fixture timeout");
    let port = server.local_addr().expect("read IPv6 fixture address").port();
    let socket = net::socket(
        net::AddressFamily::INET6,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv6 UDP socket");
    let endpoint = SocketAddress::new(IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), port);

    net::connect(&socket, endpoint).expect("connect native IPv6 UDP socket");
    assert_eq!(net::send(&socket, b"m10-v6", net::SendFlags::empty()).unwrap(), 6);

    let mut received = [0u8; 32];
    let (length, peer) = server.recv_from(&mut received).expect("receive IPv6 fixture datagram");
    assert_eq!(&received[..length], b"m10-v6");
    assert!(peer.ip().is_ipv6());
}

#[test]
fn ipv4_scope_is_rejected_instead_of_discarded() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::empty(),
        None,
    )
    .expect("create native IPv4 UDP socket");
    let endpoint = SocketAddress::new_scoped(IpAddress::V4([127, 0, 0, 1]), 9, 7);

    assert_eq!(net::connect(&socket, endpoint), Err(Errno::INVAL));
}
