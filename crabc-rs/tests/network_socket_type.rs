use crabc_rs::{net, Errno};

#[test]
fn socket_type_reads_datagram_socket_type() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an IPv4 datagram socket");

    assert_eq!(
        net::sockopt::socket_type(&socket).expect("read SO_TYPE"),
        net::SocketType::DGRAM
    );
}

#[test]
fn socket_type_rejects_a_non_socket_descriptor() {
    let file = std::fs::File::open("Cargo.toml").expect("open a regular file");

    assert_eq!(net::sockopt::socket_type(&file), Err(Errno::NOTSOCK));
}
