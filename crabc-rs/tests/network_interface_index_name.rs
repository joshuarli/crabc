use crabc_rs::net::netdevice;
use crabc_rs::Errno;

fn ioctl_socket() -> std::net::UdpSocket {
    std::net::UdpSocket::bind("127.0.0.1:0").expect("create an IPv4 datagram socket")
}

#[test]
fn network_device_index_to_name_round_trips_loopback() {
    let socket = ioctl_socket();
    let index = netdevice::name_to_index(&socket, "lo").expect("query loopback interface index");

    let inlined = netdevice::index_to_name_inlined(&socket, index)
        .expect("query loopback interface name without allocation");
    assert_eq!(inlined.as_str(), "lo");
    assert_eq!(inlined.as_bytes(), b"lo");
    assert_eq!(inlined.to_string(), "lo");

    assert_eq!(
        netdevice::index_to_name(&socket, index).expect("query loopback interface name"),
        "lo"
    );
}

#[test]
fn network_device_index_to_name_rejects_invalid_indices() {
    let socket = ioctl_socket();

    assert_eq!(
        netdevice::index_to_name_inlined(&socket, 0),
        Err(Errno::NODEV),
    );
    assert_eq!(netdevice::index_to_name(&socket, 0), Err(Errno::NODEV),);
}

#[test]
fn network_device_index_to_name_keeps_owned_result_storage_independent() {
    let socket = ioctl_socket();
    let index = netdevice::name_to_index(&socket, "lo").expect("query loopback interface index");

    let first = netdevice::index_to_name_inlined(&socket, index)
        .expect("query first loopback interface name");
    let second = netdevice::index_to_name_inlined(&socket, index)
        .expect("query second loopback interface name");

    assert_eq!(first.as_bytes(), b"lo");
    assert_eq!(second.as_bytes(), b"lo");
}
