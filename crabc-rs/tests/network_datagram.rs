use core::mem::MaybeUninit;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicUsize, Ordering};

use crabc_rs::net;
use crabc_rs::resolver::{IpAddress, SocketAddress};
use crabc_rs::Errno;

static UNIX_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn unix_socket_path(role: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "crabc-rs-native-datagram-{role}-{}-{}",
        std::process::id(),
        UNIX_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    ))
}

#[test]
fn sendto_and_recvfrom_round_trip_an_ipv4_source() {
    let receiver = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv4 datagram receiver");
    net::bind(
        &receiver,
        SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), 0),
    )
    .expect("bind native IPv4 datagram receiver");
    let destination = net::getsockname(&receiver).expect("read IPv4 datagram destination");

    let sender = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv4 datagram sender");
    let payload = b"native-sendto-v4";
    assert_eq!(
        net::sendto(&sender, payload, net::SendFlags::empty(), destination)
            .expect("send native IPv4 datagram"),
        payload.len(),
    );

    let mut buffer = [0xcc_u8; 32];
    let (initialized, received, source) =
        net::recvfrom(&receiver, &mut buffer, net::RecvFlags::empty())
            .expect("receive native IPv4 datagram");
    assert_eq!(initialized, payload.len());
    assert_eq!(received, payload.len());
    assert_eq!(&buffer[..initialized], payload);
    assert_eq!(source.ip(), IpAddress::V4([127, 0, 0, 1]));
    assert_ne!(source.port(), 0, "Linux assigns an ephemeral source port");
    assert_eq!(source.scope_id(), 0);
}

#[test]
fn sendto_and_recvfrom_round_trip_an_ipv6_source() {
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

    let receiver = net::socket(
        net::AddressFamily::INET6,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv6 datagram receiver");
    net::bind(
        &receiver,
        SocketAddress::new(
            IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            0,
        ),
    )
    .expect("bind native IPv6 datagram receiver");
    let destination = net::getsockname(&receiver).expect("read IPv6 datagram destination");

    let sender = net::socket(
        net::AddressFamily::INET6,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv6 datagram sender");
    let payload = b"native-sendto-v6";
    assert_eq!(
        net::sendto(&sender, payload, net::SendFlags::empty(), destination)
            .expect("send native IPv6 datagram"),
        payload.len(),
    );

    let mut buffer = [0xcc_u8; 32];
    let (initialized, received, source) =
        net::recvfrom(&receiver, &mut buffer, net::RecvFlags::empty())
            .expect("receive native IPv6 datagram");
    assert_eq!(initialized, payload.len());
    assert_eq!(received, payload.len());
    assert_eq!(&buffer[..initialized], payload);
    assert_eq!(
        source.ip(),
        IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
    assert_eq!(source.scope_id(), 0);
}

#[test]
fn recvfrom_reports_full_truncated_length_but_only_initializes_the_buffer_prefix() {
    let receiver = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv4 datagram receiver");
    net::bind(
        &receiver,
        SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), 0),
    )
    .expect("bind native IPv4 datagram receiver");
    let destination = net::getsockname(&receiver).expect("read IPv4 datagram destination");
    let sender = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv4 datagram sender");
    let payload = b"0123456789";
    net::sendto(&sender, payload, net::SendFlags::empty(), destination)
        .expect("send truncation fixture");

    let mut buffer = [MaybeUninit::<u8>::uninit(); 4];
    let ((initialized, remaining), received, source) =
        net::recvfrom(&receiver, &mut buffer, net::RecvFlags::TRUNC)
            .expect("receive truncation fixture");
    assert_eq!(received, payload.len());
    assert_eq!(&*initialized, &payload[..4]);
    assert!(matches!(source.ip(), IpAddress::V4(_)));
    assert!(remaining.is_empty());
}

#[test]
fn sendto_rejects_an_ipv4_scope_instead_of_discarding_it() {
    let sender = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv4 datagram sender");
    let destination = SocketAddress::new_scoped(IpAddress::V4([127, 0, 0, 1]), 9, 7);

    assert_eq!(
        net::sendto(
            &sender,
            b"invalid-scope",
            net::SendFlags::empty(),
            destination
        ),
        Err(Errno::INVAL),
    );
}

#[test]
fn recvfrom_rejects_an_unrepresented_source_family() {
    let receiver_path = unix_socket_path("receiver");
    let sender_path = unix_socket_path("sender");
    let receiver = UnixDatagram::bind(&receiver_path).expect("bind Unix datagram receiver");
    let sender = UnixDatagram::bind(&sender_path).expect("bind Unix datagram sender");
    sender
        .send_to(b"unsupported-family", &receiver_path)
        .expect("send Unix datagram source fixture");

    let mut buffer = [0xcc_u8; 32];
    assert_eq!(
        net::recvfrom(&receiver, &mut buffer, net::RecvFlags::empty()),
        Err(Errno::AFNOSUPPORT),
    );

    drop(sender);
    drop(receiver);
    std::fs::remove_file(sender_path).expect("remove Unix sender fixture");
    std::fs::remove_file(receiver_path).expect("remove Unix receiver fixture");
}
