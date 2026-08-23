use api::{net, net::sockopt};

fn main() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("create an IPv4 datagram socket");
    assert_eq!(
        sockopt::socket_type(&socket).expect("read SO_TYPE"),
        net::SocketType::DGRAM,
    );
    println!("native-socket-type ok");
}
