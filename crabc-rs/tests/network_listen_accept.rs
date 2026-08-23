use std::io::Write;
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};

use crabc_rs::{io, net, Errno};
use crabc_rs::resolver::{IpAddress, SocketAddress};

fn native_listener() -> (crabc_rs::OwnedFd, SocketAddress) {
    let listener = net::socket(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create native IPv4 stream listener");
    net::bind(
        &listener,
        SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), 0),
    )
    .expect("bind native IPv4 stream listener");
    net::listen(&listener, 4).expect("enable native IPv4 stream listener");
    let address = net::getsockname(&listener).expect("read native listener address");
    (listener, address)
}

#[test]
fn listen_and_accept_return_an_owned_stream_descriptor() {
    let (listener, address) = native_listener();
    let mut client = TcpStream::connect(("127.0.0.1", address.port()))
        .expect("connect standard-library client to native listener");
    let accepted = net::accept(&listener).expect("accept pending native connection");

    client
        .write_all(b"native-accept")
        .expect("write through standard-library client");
    let mut received = [0u8; 32];
    let length = io::read(&accepted, &mut received).expect("read through accepted owner");
    assert_eq!(&received[..length], b"native-accept");
}

#[test]
fn accept4_applies_cloexec_and_nonblock_atomically() {
    let (listener, address) = native_listener();
    assert!(matches!(
        net::accept4(&listener, net::SocketFlags::from_bits_retain(0x4)),
        Err(Errno::INVAL)
    ));
    let _client = TcpStream::connect(("127.0.0.1", address.port()))
        .expect("connect standard-library client to native listener");
    let accepted = net::accept4(
        &listener,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
    )
    .expect("accept4 pending native connection");

    assert!(
        io::fcntl_getfd(&accepted)
            .expect("read accepted descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
        "SOCK_CLOEXEC must become FD_CLOEXEC on an accept4 result",
    );
    let mut byte = [0u8; 1];
    assert_eq!(io::read(&accepted, &mut byte), Err(Errno::AGAIN));
}

#[test]
fn acceptfrom_decodes_the_strict_ipv4_peer_address() {
    let (listener, address) = native_listener();
    let client = TcpStream::connect(("127.0.0.1", address.port()))
        .expect("connect standard-library client to native listener");
    let client_port = client
        .local_addr()
        .expect("read standard-library client address")
        .port();

    let (accepted, peer) = net::acceptfrom(&listener).expect("accept and decode peer address");
    assert_eq!(
        peer,
        SocketAddress::new(IpAddress::V4([127, 0, 0, 1]), client_port)
    );
    drop(accepted);
}

#[test]
fn acceptfrom_with_decodes_the_peer_and_preserves_accept4_flags() {
    let (listener, address) = native_listener();
    let _client = TcpStream::connect(("127.0.0.1", address.port()))
        .expect("connect standard-library client to native listener");
    let (accepted, peer) = net::acceptfrom_with(
        &listener,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
    )
    .expect("accept4 and decode peer address");

    assert_eq!(peer.ip(), IpAddress::V4([127, 0, 0, 1]));
    assert!(
        io::fcntl_getfd(&accepted)
            .expect("read accepted descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
    );
}

#[test]
fn acceptfrom_rejects_an_unrepresented_socket_family() {
    let path = std::env::temp_dir().join(format!(
        "crabc-native-accept-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let listener = UnixListener::bind(&path).expect("bind isolated Unix listener");
    let client = UnixStream::connect(&path).expect("connect isolated Unix client");

    assert!(matches!(
        net::acceptfrom(&listener),
        Err(Errno::AFNOSUPPORT)
    ));

    drop(client);
    drop(listener);
    std::fs::remove_file(path).expect("remove isolated Unix socket path");
}

#[test]
fn accept_with_uses_the_typed_accept_flags() {
    let (listener, address) = native_listener();
    let _client = TcpStream::connect(("127.0.0.1", address.port()))
        .expect("connect standard-library client to native listener");
    let accepted = net::accept_with(&listener, net::SocketFlags::CLOEXEC)
        .expect("accept4 pending native connection through accept_with");
    assert!(io::fcntl_getfd(&accepted).unwrap().contains(io::FdFlags::CLOEXEC));
}
