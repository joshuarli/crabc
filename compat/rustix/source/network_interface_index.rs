use api::net::netdevice;

fn main() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("create an IPv4 datagram socket");
    let index = netdevice::name_to_index(&socket, "lo")
        .expect("query loopback interface index");
    assert!(index > 0);
    println!("native-network-interface-index ok");
}
