use crabc_rs::{net, Errno};

#[test]
fn reuseaddr_round_trips_as_a_typed_boolean_option() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an IPv4 datagram socket");

    assert!(!net::socket_reuseaddr(&socket).expect("read default SO_REUSEADDR"));
    net::set_socket_reuseaddr(&socket, true).expect("enable SO_REUSEADDR");
    assert!(net::socket_reuseaddr(&socket).expect("read enabled SO_REUSEADDR"));
    net::set_socket_reuseaddr(&socket, false).expect("disable SO_REUSEADDR");
    assert!(!net::socket_reuseaddr(&socket).expect("read disabled SO_REUSEADDR"));
}

#[test]
fn reuseaddr_preserves_kernel_not_socket_error() {
    let file = std::fs::File::open("Cargo.toml").expect("open a regular file");

    assert_eq!(net::socket_reuseaddr(&file), Err(Errno::NOTSOCK));
    assert_eq!(net::set_socket_reuseaddr(&file, true), Err(Errno::NOTSOCK));
}
