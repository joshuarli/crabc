use crabc_rs::{net, Errno};

#[test]
fn socket_protocol_reads_udp_protocol() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an IPv4 datagram socket");

    assert_eq!(
        net::sockopt::socket_protocol(&socket)
            .expect("read SO_PROTOCOL")
            .map(|protocol| protocol.as_raw().get()),
        Some(17)
    );
}

#[test]
fn socket_protocol_maps_a_zero_kernel_protocol_to_none() {
    let socket = net::socket(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create a Unix stream socket");

    assert_eq!(
        net::sockopt::socket_protocol(&socket).expect("read SO_PROTOCOL"),
        None
    );
}

#[test]
fn socket_protocol_rejects_a_non_socket_descriptor() {
    let file = std::fs::File::open("Cargo.toml").expect("open a regular file");

    assert_eq!(net::sockopt::socket_protocol(&file), Err(Errno::NOTSOCK));
}
