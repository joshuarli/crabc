use api::net::sockopt;

fn main() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("create an IPv4 datagram socket");

    assert!(!sockopt::socket_broadcast(&socket).expect("read default BROADCAST"));
    sockopt::set_socket_broadcast(&socket, true).expect("enable BROADCAST");
    assert!(sockopt::socket_broadcast(&socket).expect("read enabled BROADCAST"));
    sockopt::set_socket_broadcast(&socket, false).expect("disable BROADCAST");
    assert!(!sockopt::socket_broadcast(&socket).expect("read disabled BROADCAST"));
    println!("m10-socket-broadcast ok");
}
