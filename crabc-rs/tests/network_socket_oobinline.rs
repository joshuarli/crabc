use crabc_rs::{net, Errno};

#[test]
fn socket_oobinline_round_trips_as_a_typed_boolean_option() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an IPv4 stream socket");

    assert!(!net::sockopt::socket_oobinline(&socket).expect("read default SO_OOBINLINE"));
    net::sockopt::set_socket_oobinline(&socket, true).expect("enable SO_OOBINLINE");
    assert!(net::sockopt::socket_oobinline(&socket).expect("read enabled SO_OOBINLINE"));
    net::sockopt::set_socket_oobinline(&socket, false).expect("disable SO_OOBINLINE");
    assert!(!net::sockopt::socket_oobinline(&socket).expect("read disabled SO_OOBINLINE"));
}

#[test]
fn socket_oobinline_preserves_kernel_not_socket_error() {
    let file = std::fs::File::open("Cargo.toml").expect("open a regular file");

    assert_eq!(net::sockopt::socket_oobinline(&file), Err(Errno::NOTSOCK));
    assert_eq!(
        net::sockopt::set_socket_oobinline(&file, true),
        Err(Errno::NOTSOCK)
    );
}
