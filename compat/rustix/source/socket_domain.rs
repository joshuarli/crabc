use api::{net, net::sockopt};

fn main() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("create an IPv4 datagram socket");

    assert_eq!(
        sockopt::socket_domain(&socket).expect("read socket domain"),
        net::AddressFamily::INET,
    );
    println!("native-socket-domain ok");
}
