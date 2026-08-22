use crabc_rs::{net, Errno};

#[test]
fn socket_domain_reports_ipv4_and_ipv6_families() {
    let ipv4 = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an IPv4 datagram socket");
    assert_eq!(
        net::sockopt::socket_domain(&ipv4).expect("read IPv4 SO_DOMAIN"),
        net::AddressFamily::INET
    );

    let ipv6 = net::socket(
        net::AddressFamily::INET6,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an IPv6 datagram socket");
    assert_eq!(
        net::sockopt::socket_domain(&ipv6).expect("read IPv6 SO_DOMAIN"),
        net::AddressFamily::INET6
    );
}

#[test]
fn socket_domain_rejects_a_non_socket_descriptor() {
    let file = std::fs::File::open("Cargo.toml").expect("open a regular file");

    assert_eq!(net::sockopt::socket_domain(&file), Err(Errno::NOTSOCK));
}
