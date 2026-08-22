use api::net::sockopt;

fn main() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("create an IPv4 datagram socket");
    let first = sockopt::socket_cookie(&socket).expect("read first socket cookie");
    let second = sockopt::socket_cookie(&socket).expect("read second socket cookie");

    assert_eq!(first, second);
    println!("m10-socket-cookie ok");
}
