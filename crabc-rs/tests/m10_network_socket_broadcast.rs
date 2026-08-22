use crabc_rs::{net, Errno};

#[test]
fn socket_broadcast_round_trips_as_a_typed_boolean_option() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an unbound IPv4 datagram socket");

    assert!(!net::sockopt::socket_broadcast(&socket).expect("read default SO_BROADCAST"));
    net::sockopt::set_socket_broadcast(&socket, true).expect("enable SO_BROADCAST");
    assert!(net::sockopt::socket_broadcast(&socket).expect("read enabled SO_BROADCAST"));
    net::sockopt::set_socket_broadcast(&socket, false).expect("disable SO_BROADCAST");
    assert!(!net::sockopt::socket_broadcast(&socket).expect("read disabled SO_BROADCAST"));
}

#[test]
fn socket_broadcast_rejects_a_non_socket_descriptor() {
    let file = std::fs::File::open("Cargo.toml").expect("open a regular file");

    assert_eq!(net::sockopt::socket_broadcast(&file), Err(Errno::NOTSOCK));
    assert_eq!(
        net::sockopt::set_socket_broadcast(&file, true),
        Err(Errno::NOTSOCK)
    );
}
