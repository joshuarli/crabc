use api::net::sockopt;

fn main() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("create an IPv4 datagram socket");
    assert_eq!(
        sockopt::socket_protocol(&socket)
            .expect("read SO_PROTOCOL")
            .map(|protocol| protocol.as_raw().get()),
        Some(17),
    );
    println!("native-socket-protocol ok");
}
