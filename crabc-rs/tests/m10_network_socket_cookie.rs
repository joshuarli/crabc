use crabc_rs::{net, Errno};

#[test]
fn socket_cookie_is_stable_for_repeated_reads() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an IPv4 datagram socket");

    let first = net::sockopt::socket_cookie(&socket).expect("read SO_COOKIE");
    let second = net::sockopt::socket_cookie(&socket).expect("read SO_COOKIE again");
    assert_eq!(first, second);
}

#[test]
fn socket_cookie_rejects_a_non_socket_descriptor() {
    let file = std::fs::File::open("Cargo.toml").expect("open a regular file");

    assert_eq!(net::sockopt::socket_cookie(&file), Err(Errno::NOTSOCK));
}
