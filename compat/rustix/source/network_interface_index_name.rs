use api::net::netdevice;

fn main() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("create an IPv4 datagram socket");
    let index = netdevice::name_to_index(&socket, "lo")
        .expect("query loopback interface index");

    let inlined = netdevice::index_to_name_inlined(&socket, index)
        .expect("query loopback interface name without allocation");
    assert_eq!(inlined.as_str(), "lo");
    assert_eq!(inlined.as_bytes(), b"lo");
    assert_eq!(
        netdevice::index_to_name(&socket, index)
            .expect("query loopback interface name"),
        "lo"
    );
    assert_eq!(
        netdevice::index_to_name_inlined(&socket, 0)
            .expect_err("reject an invalid interface index")
            .raw_os_error(),
        19,
    );

    println!("native-network-interface-index-name ok");
}
